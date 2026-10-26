package tenant

import (
	"context"
	"errors"
	"strings"

	"github.com/biairmal/go-sdk/lib/common/dto"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/scope"
)

// Service holds the tenant rules. It knows nothing about HTTP.
type Service struct {
	cfg   Config
	repo  *Repository
	audit AuditWriter
	log   logger.Logger
	// v validates admin request bodies; only the admin routes use it.
	v validator.Validator
	// onboarding copies the template roles and invites the first admin when
	// a tenant is created. It is the one back edge (TRD 3.1), set by
	// internal/app after auth is built; nil skips both steps.
	onboarding Onboarding
}

// SetOnboarding wires the tenant-creation back edge. internal/app calls it
// once, after the rbac and auth modules exist.
func (s *Service) SetOnboarding(o Onboarding) { s.onboarding = o }

// NewService returns a Service. audit may be nil, which skips the audit
// writes; log may be nil.
func NewService(cfg Config, repo *Repository, auditWriter AuditWriter, log logger.Logger) *Service {
	if log == nil {
		log = logger.NewNoOp()
	}
	return &Service{cfg: cfg, repo: repo, audit: auditWriter, log: log}
}

// EnsureDefault creates the configured default tenant if it is missing and
// returns it. It runs on every start, so it must be idempotent: a second
// start, or a second pod, finds the existing row and changes nothing.
func (s *Service) EnsureDefault(ctx context.Context) (*Tenant, error) {
	t, created, err := s.repo.EnsureBySlug(ctx, s.cfg.DefaultTenantSlug, defaultTenantName)
	if err != nil {
		return nil, err
	}
	if !created {
		return t, nil
	}
	s.log.InfoWithContext(ctx, "default tenant created", logger.F("tenant_slug", t.Slug))
	if err := s.writeAudit(ctx, &AuditEvent{
		TenantID: t.ID, Action: ActionTenantCreate, TargetType: TargetTenant, TargetID: t.ID.String(),
		After: map[string]any{"slug": t.Slug, "name": t.Name, "status": t.Status},
	}); err != nil {
		return nil, err
	}
	return t, nil
}

// defaultTenantName is the display name of the tenant created on first start.
// An admin can rename it later.
const defaultTenantName = "Default"

// DefaultID returns the default tenant's ID, which single mode uses as the
// only tenant and the super admin's home tenant.
func (s *Service) DefaultID(ctx context.Context) (uuid.UUID, error) {
	t, err := s.repo.BySlug(ctx, s.cfg.DefaultTenantSlug)
	if err != nil {
		return uuid.Nil, err
	}
	return t.ID, nil
}

// BySlug returns the tenant with this slug, or errorz.NotFound.
func (s *Service) BySlug(ctx context.Context, slug string) (*Tenant, error) {
	return s.repo.BySlug(ctx, slug)
}

// ByID returns one tenant.
func (s *Service) ByID(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	return s.repo.ByID(ctx, id)
}

// List returns every tenant. internal/app uses it at startup to seed roles
// into each one, so rbac does not have to list tenants itself.
func (s *Service) List(ctx context.Context) ([]Tenant, error) { return s.repo.List(ctx) }

// Current returns the tenant of the calling token. The tenant comes only from
// the token claim, never from a request parameter.
func (s *Service) Current(ctx context.Context) (*Tenant, error) {
	id, err := scope.Tenant(ctx)
	if err != nil {
		return nil, err
	}
	return s.repo.ByID(ctx, id)
}

// ListTenants returns one page of tenants (9.7). status and search are
// optional filters.
func (s *Service) ListTenants(
	ctx context.Context, status, search string, page, size int,
) (*TenantPageResponse, error) {
	rows, total, err := s.repo.ListPage(ctx, status, strings.TrimSpace(search), size, (page-1)*size)
	if err != nil {
		return nil, err
	}
	items := make([]*TenantSummaryResponse, 0, len(rows))
	for i := range rows {
		r := &rows[i]
		items = append(items, &TenantSummaryResponse{
			ID: r.ID.String(), Slug: r.Slug, Name: r.Name, Status: r.Status,
			MemberCount: r.MemberCount, CreatedAt: r.CreatedAt.UTC(), Version: r.Version,
		})
	}
	return dto.NewPageResponse(items, total, page, size), nil
}

// GetTenant returns one tenant, or errorz.NotFound.
func (s *Service) GetTenant(ctx context.Context, id uuid.UUID) (*TenantResponse, error) {
	t, err := s.repo.ByID(ctx, id)
	if err != nil {
		return nil, err
	}
	return newTenantResponse(t), nil
}

// CreateTenant creates a tenant, copies the template roles into it and
// invites the first admin, all in one transaction (9.7). A slug already in
// use is DUPLICATE.
func (s *Service) CreateTenant(ctx context.Context, in *CreateTenantRequest) (*TenantResponse, error) {
	in.Slug = strings.TrimSpace(in.Slug)
	in.Name = strings.TrimSpace(in.Name)
	in.FirstAdminEmail = strings.TrimSpace(in.FirstAdminEmail)
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	if !slugPattern.MatchString(in.Slug) {
		return nil, errorz.BadRequest().WithMessage("slug must match "+slugPattern.String()).
			WithMeta(apierr.MetaFields, map[string]string{"slug": "must match " + slugPattern.String()})
	}
	actorID, err := scope.User(ctx)
	if err != nil {
		return nil, err
	}
	var out *TenantResponse
	err = database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		t, err := s.repo.Create(ctx, in.Slug, in.Name)
		if err != nil {
			return err
		}
		if s.onboarding != nil {
			if err := s.onboarding.CopyTemplateRoles(ctx, t.ID); err != nil {
				return err
			}
			if err := s.onboarding.InviteFirstAdmin(ctx, t.ID, actorID, in.FirstAdminEmail); err != nil {
				return err
			}
		}
		out = newTenantResponse(t)
		return s.writeAudit(ctx, &AuditEvent{
			TenantID: t.ID, ActorID: actorID, Action: ActionTenantCreate,
			TargetType: TargetTenant, TargetID: t.ID.String(),
			After: map[string]any{"slug": t.Slug, "name": t.Name, "first_admin_email": in.FirstAdminEmail},
		})
	})
	return out, err
}

// UpdateTenant renames a tenant or changes its status (9.7). The default
// tenant cannot be suspended. Requires the current version (If-Match).
func (s *Service) UpdateTenant(
	ctx context.Context, id uuid.UUID, version int, in *UpdateTenantRequest,
) (*TenantResponse, error) {
	if in.Name != nil {
		name := strings.TrimSpace(*in.Name)
		in.Name = &name
	}
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	actorID, err := scope.User(ctx)
	if err != nil {
		return nil, err
	}
	var out *TenantResponse
	err = database.WithTx(ctx, s.repo.db, func(ctx context.Context) error {
		t, err := s.repo.ByID(ctx, id)
		if err != nil {
			return err
		}
		if t.Version != version {
			return apierr.New(apierr.ReasonVersionConflict)
		}
		name, status := t.Name, t.Status
		if in.Name != nil {
			name = *in.Name
		}
		if in.Status != nil {
			status = *in.Status
		}
		if status == StatusSuspended && t.Slug == s.cfg.DefaultTenantSlug {
			return errorz.BadRequest().WithMessage("the default tenant cannot be suspended").
				WithMeta(apierr.MetaFields, map[string]string{"status": "the default tenant cannot be suspended"})
		}
		updated, err := s.repo.Update(ctx, id, version, name, status)
		if err != nil {
			return err
		}
		out = newTenantResponse(updated)
		return s.writeAudit(ctx, &AuditEvent{
			TenantID: id, ActorID: actorID, Action: statusChangeAction(t.Status, status),
			TargetType: TargetTenant, TargetID: id.String(),
			Before: map[string]any{"name": t.Name, "status": t.Status},
			After:  map[string]any{"name": updated.Name, "status": updated.Status},
		})
	})
	return out, err
}

// statusChangeAction names the audit action for a tenant update: a suspend or
// reactivate when the status changed, otherwise a plain update.
func statusChangeAction(before, after string) string {
	switch {
	case before != StatusSuspended && after == StatusSuspended:
		return ActionTenantSuspend
	case before == StatusSuspended && after == StatusActive:
		return ActionTenantReactivate
	default:
		return ActionTenantUpdate
	}
}

// AddMember makes a user a member of a tenant and records it.
func (s *Service) AddMember(ctx context.Context, tenantID, userID uuid.UUID, status string) error {
	if err := s.repo.AddMember(ctx, tenantID, userID, status); err != nil {
		return err
	}
	return s.writeAudit(ctx, &AuditEvent{
		TenantID: tenantID, Action: ActionMemberAdd,
		TargetType: TargetMembership, TargetID: userID.String(),
		After: map[string]any{"status": status},
	})
}

// EnsureActiveMember makes a user an active member of a tenant: it adds the
// membership when there is none, reactivates an invited or removed one, and
// leaves an active or disabled one alone: only an admin enables a membership. Every change is audited; a no-op is not.
func (s *Service) EnsureActiveMember(ctx context.Context, tenantID, userID uuid.UUID) error {
	m, err := s.repo.Member(ctx, tenantID, userID)
	switch {
	case errors.Is(err, errorz.ErrNotFound):
		return s.AddMember(ctx, tenantID, userID, MemberActive)
	case err != nil:
		return err
	case m.Active(), m.Status == MemberDisabled:
		return nil
	}
	if err := s.repo.SetMemberStatus(ctx, tenantID, userID, MemberActive); err != nil {
		return err
	}
	return s.writeAudit(ctx, &AuditEvent{
		TenantID: tenantID, Action: ActionMemberAdd,
		TargetType: TargetMembership, TargetID: userID.String(),
		Before: map[string]any{"status": m.Status},
		After:  map[string]any{"status": MemberActive},
	})
}

// InviteMember makes a user an invited member of a tenant: it adds the
// membership when there is none and re-invites a removed one, and leaves an
// invited, active or disabled one alone. It returns the status before the call ("" for
// none). Every change is audited.
func (s *Service) InviteMember(ctx context.Context, tenantID, userID uuid.UUID) (string, error) {
	m, err := s.repo.Member(ctx, tenantID, userID)
	switch {
	case errors.Is(err, errorz.ErrNotFound):
		return "", s.AddMember(ctx, tenantID, userID, MemberInvited)
	case err != nil:
		return "", err
	case m.Status != MemberRemoved:
		return m.Status, nil
	}
	if err := s.repo.SetMemberStatus(ctx, tenantID, userID, MemberInvited); err != nil {
		return "", err
	}
	return m.Status, s.writeAudit(ctx, &AuditEvent{
		TenantID: tenantID, Action: ActionMemberAdd,
		TargetType: TargetMembership, TargetID: userID.String(),
		Before: map[string]any{"status": m.Status},
		After:  map[string]any{"status": MemberInvited},
	})
}

// DisableMember blocks a user in one tenant. Only an admin's enable undoes it.
func (s *Service) DisableMember(ctx context.Context, tenantID, userID uuid.UUID) error {
	return s.repo.SetMemberStatus(ctx, tenantID, userID, MemberDisabled)
}

// EnableMember lets a disabled membership act in its tenant again.
func (s *Service) EnableMember(ctx context.Context, tenantID, userID uuid.UUID) error {
	return s.repo.SetMemberStatus(ctx, tenantID, userID, MemberActive)
}

// RemoveMember marks a membership removed and records who did it. The row
// stays, so the user's history in the tenant remains readable.
func (s *Service) RemoveMember(ctx context.Context, tenantID, userID, actorID uuid.UUID) error {
	m, err := s.repo.Member(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if err := s.repo.SetMemberStatus(ctx, tenantID, userID, MemberRemoved); err != nil {
		return err
	}
	return s.writeAudit(ctx, &AuditEvent{
		TenantID: tenantID, ActorID: actorID, Action: ActionMemberRemove,
		TargetType: TargetMembership, TargetID: userID.String(),
		Before: map[string]any{"status": m.Status},
		After:  map[string]any{"status": MemberRemoved},
	})
}

// Member returns one membership.
func (s *Service) Member(ctx context.Context, tenantID, userID uuid.UUID) (*Member, error) {
	return s.repo.Member(ctx, tenantID, userID)
}

// MembershipsOf lists the tenants a user belongs to.
func (s *Service) MembershipsOf(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	return s.repo.MembershipsOf(ctx, userID)
}

// writeAudit records an event when an audit writer is wired.
func (s *Service) writeAudit(ctx context.Context, e *AuditEvent) error {
	if s.audit == nil {
		return nil
	}
	return s.audit.Write(ctx, e)
}
