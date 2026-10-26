package auth

import (
	"context"
	"errors"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/scope"
)

// Switches runs POST /v1/auth/switch-tenant (APP_FLOW 11): an authenticated
// user trades their token for one in another of their tenants, in a new
// refresh family. The old family stays valid for the old tenant. Multi mode
// only; the route answers 404 in single mode.
type Switches struct {
	tenancy  string
	tx       txFunc
	v        validator.Validator
	users    Users
	tenants  Tenants
	sessions Sessions
	audit    AuditWriter
	issue    *tokenIssuer
	log      logger.Logger
}

// Switch issues a token response for tenant_id. A user who is not an active
// member is NOT_A_MEMBER, a disabled membership is ACCOUNT_DISABLED, and a
// suspended tenant is TENANT_SUSPENDED. The super admin may switch into any
// tenant, suspended included.
func (s *Switches) Switch(ctx context.Context, in *SwitchTenantRequest, d Device) (*TokenResponse, error) {
	if s.tenancy != tenancyMulti {
		return nil, errorz.NotFound().WithMessage("route not found")
	}
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	userID, err := scope.User(ctx)
	if err != nil {
		return nil, err
	}
	a, err := s.users.Get(ctx, userID)
	if err != nil {
		return nil, err
	}
	if a.Status != StatusActive {
		return nil, apierr.New(apierr.ReasonAccountDisabled)
	}
	tenant, err := s.target(ctx, a, in.TenantID)
	if err != nil {
		return nil, err
	}
	var resp *TokenResponse
	err = s.tx(ctx, func(ctx context.Context) error {
		issued, err := s.sessions.Issue(ctx, a.ID, tenant.ID, d)
		if err != nil {
			return err
		}
		resp, err = s.issue.session(ctx, a, tenant, issued)
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, &AuditEvent{
			TenantID: tenant.ID, ActorID: a.ID, Action: ActionSwitchTenant,
			TargetType: TargetUser, TargetID: a.ID.String(),
			After: map[string]any{"tenant_id": tenant.ID.String()},
		})
	})
	return resp, err
}

// target resolves the tenant the caller may switch into. The super admin may
// enter any existing tenant; everyone else needs an active membership of a
// tenant that is not suspended.
func (s *Switches) target(ctx context.Context, a *Account, tenantID uuid.UUID) (*TenantInfo, error) {
	if a.IsSuperAdmin {
		t, err := s.tenants.Tenant(ctx, tenantID)
		if err != nil {
			return nil, notAMemberOr(err)
		}
		return t, nil
	}
	all, err := s.tenants.Memberships(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	for i := range all {
		m := &all[i]
		if m.Tenant.ID != tenantID {
			continue
		}
		switch {
		case m.Status == memberDisabled:
			return nil, apierr.New(apierr.ReasonAccountDisabled)
		case !m.Active: // invited or removed: not a member who can act
			return nil, apierr.New(apierr.ReasonNotAMember)
		case !m.Tenant.Active:
			return nil, apierr.New(apierr.ReasonTenantSuspended)
		default:
			return &m.Tenant, nil
		}
	}
	return nil, apierr.New(apierr.ReasonNotAMember)
}

// notAMemberOr maps a missing tenant to NOT_A_MEMBER, so a super admin cannot
// probe which tenant IDs exist, and passes any other error through.
func notAMemberOr(err error) error {
	if errors.Is(err, errorz.ErrNotFound) {
		return apierr.New(apierr.ReasonNotAMember)
	}
	return err
}
