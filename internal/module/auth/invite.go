package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/response"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/module/auth/onetime"
	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/auth/templates"
	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/httpx"
	"github.com/biairmal/go-identity/internal/platform/mail"
	"github.com/biairmal/go-identity/internal/platform/requestip"
)

// inviteTTL is how long an invite link stays valid (APP_FLOW 10).
const inviteTTL = 7 * 24 * time.Hour

// Membership status values, as the tenant module stores them.
const (
	memberInvited  = "invited"
	memberActive   = "active"
	memberDisabled = "disabled"
)

// Invites runs invite, preview and accept (APP_FLOW 10). An invite finds or
// creates the account (pending, without a password), makes it an invited
// member of the admin's tenant and mails a one-time link carrying the role
// IDs. Accepting spends the link, sets a password only when the account has
// none, verifies the email, activates the membership, grants the roles and
// signs the user in to that tenant.
type Invites struct {
	cfg      *Config
	db       *sqlkit.DB
	v        validator.Validator
	users    Users
	tenants  Tenants
	roles    Roles
	sessions Sessions
	audit    AuditWriter
	outbox   mail.Enqueuer
	tokens   *onetime.Service
	tokRepo  *onetime.Repository
	issue    *tokenIssuer
	clock    clock.Clock
	log      logger.Logger
}

// invitePayload is stored with the invite token. It holds no secret.
type invitePayload struct {
	RoleIDs   []uuid.UUID `json:"role_ids"`
	InvitedBy uuid.UUID   `json:"invited_by"`
}

// Invite invites email into the caller's tenant with role IDs the caller may
// grant. Re-inviting an invited or removed member replaces the earlier link;
// an active or disabled member is 409 ALREADY_MEMBER, and the super admin is
// SUPER_ADMIN_PROTECTED.
func (s *Invites) Invite(ctx context.Context, in *InviteRequest) error {
	in.Email = strings.TrimSpace(in.Email)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if err := s.v.ValidateStruct(in); err != nil {
		return err
	}
	actorID, tenantID, err := caller(ctx)
	if err != nil {
		return err
	}
	if err := s.roles.CheckGrantable(ctx, in.RoleIDs); err != nil {
		return err
	}
	return database.WithTx(ctx, s.db, func(ctx context.Context) error {
		return s.invite(ctx, tenantID, actorID, in.Email, in.DisplayName, in.RoleIDs)
	})
}

// InviteToTenant invites email into tenantID as its first admin, granting
// roleIDs, recording invitedBy as the inviter. It is the tenant-creation path
// (T6.1): the tenant is the new one, so it is explicit, and it joins the
// caller's transaction instead of opening its own, so the invite rolls back
// with the tenant if anything fails.
func (s *Invites) InviteToTenant(
	ctx context.Context, tenantID, invitedBy uuid.UUID, email string, roleIDs []uuid.UUID,
) error {
	return s.invite(ctx, tenantID, invitedBy, strings.TrimSpace(email), "", roleIDs)
}

// invite runs the shared invite work in the caller's transaction: find or
// create the account, make it an invited member (an active or disabled member
// is ALREADY_MEMBER), replace any earlier link, mail a new one and audit it.
func (s *Invites) invite(
	ctx context.Context, tenantID, actorID uuid.UUID, email, displayName string, roleIDs []uuid.UUID,
) error {
	if roleIDs == nil {
		roleIDs = []uuid.UUID{}
	}
	payload, err := json.Marshal(invitePayload{RoleIDs: roleIDs, InvitedBy: actorID})
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: encode invite")
	}
	tenant, err := s.tenants.Tenant(ctx, tenantID)
	if err != nil {
		return err
	}
	inviter, err := s.users.Get(ctx, actorID)
	if err != nil {
		return err
	}
	a, created, err := s.findOrCreate(ctx, &InviteRequest{Email: email, DisplayName: displayName})
	if err != nil {
		return err
	}
	previous, err := s.tenants.InviteMember(ctx, tenantID, a.ID)
	if err != nil {
		return err
	}
	if previous == memberActive || previous == memberDisabled {
		return apierr.New(apierr.ReasonAlreadyMember)
	}
	if err := s.tokRepo.DeleteUnusedForUserInTenant(ctx, a.ID, tenantID, onetime.PurposeInvite); err != nil {
		return err
	}
	issued, err := s.tokens.Create(ctx, a.ID, onetime.PurposeInvite, inviteTTL,
		onetime.Options{TenantID: &tenantID, Payload: payload})
	if err != nil {
		return err
	}
	if err := mail.Queue(ctx, s.outbox, templates.InviteMessage(a.Email, issued.Raw, map[string]string{
		"InviterName": inviter.DisplayName, "TenantName": tenant.Name,
	})); err != nil {
		return err
	}
	return s.audit.Write(ctx, &AuditEvent{
		TenantID: tenantID, ActorID: actorID, Action: ActionUserInvite,
		TargetType: TargetUser, TargetID: a.ID.String(),
		After: map[string]any{"role_ids": roleIDs, "new_account": created},
	})
}

// findOrCreate returns the account with the invited address, creating a
// pending one without a password when there is none.
func (s *Invites) findOrCreate(ctx context.Context, in *InviteRequest) (*Account, bool, error) {
	a, err := s.users.FindByEmail(ctx, in.Email)
	if err == nil {
		if a.IsSuperAdmin {
			return nil, false, apierr.New(apierr.ReasonSuperAdminProtected)
		}
		return a, false, nil
	}
	if !errors.Is(err, errorz.ErrNotFound) {
		return nil, false, err
	}
	id, err := s.users.Create(ctx, &NewAccount{Email: in.Email, DisplayName: in.DisplayName, Status: StatusPending})
	if err != nil {
		return nil, false, err
	}
	a, err = s.users.Get(ctx, id)
	return a, true, err
}

// Preview describes an unspent invite for the accept screen.
func (s *Invites) Preview(ctx context.Context, raw string) (*InvitePreviewResponse, error) {
	t, err := s.tokens.Peek(ctx, raw, onetime.PurposeInvite)
	if err != nil {
		return nil, tokenError(err)
	}
	a, tenant, err := s.invitee(ctx, t)
	if err != nil {
		return nil, err
	}
	has, err := s.hasPassword(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	return &InvitePreviewResponse{
		Tenant: InviteTenantResponse{Name: tenant.Name}, EmailMasked: maskEmail(a.Email), HasPassword: has,
	}, nil
}

// Accept spends an invite and signs the invitee in to its tenant.
func (s *Invites) Accept(ctx context.Context, in *AcceptInviteRequest, d Device) (*TokenResponse, error) {
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	var hash string
	if in.Password != "" {
		if err := checkPassword("password", in.Password, s.cfg.Providers.Password.MinLength); err != nil {
			return nil, err
		}
		var err error
		if hash, err = password.Hash(in.Password); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: hash password")
		}
	}
	var out *TokenResponse
	err := database.WithTx(ctx, s.db, func(ctx context.Context) error {
		t, err := s.tokens.Consume(ctx, in.Token, onetime.PurposeInvite)
		if err != nil {
			return tokenError(err)
		}
		a, tenant, err := s.invitee(ctx, t)
		if err != nil {
			return err
		}
		if err := s.join(ctx, t, a, tenant, in, hash); err != nil {
			return err
		}
		if a, err = s.users.Get(ctx, a.ID); err != nil {
			return err
		}
		issued, err := s.sessions.Issue(ctx, a.ID, tenant.ID, d)
		if err != nil {
			return err
		}
		out, err = s.issue.session(ctx, a, tenant, issued)
		return err
	})
	return out, err
}

// join applies an accepted invite: the password if the account has none, the
// display name, a verified email, an active membership, the roles and the
// audit row.
func (s *Invites) join(
	ctx context.Context, t *onetime.Token, a *Account, tenant *TenantInfo, in *AcceptInviteRequest, hash string,
) error {
	has, err := s.hasPassword(ctx, a.ID)
	if err != nil {
		return err
	}
	if !has {
		if hash == "" {
			return apierr.WithFields(apierr.ReasonPasswordPolicy, map[string]string{"password": "required"})
		}
		if err := s.users.SetPassword(ctx, a.ID, hash); err != nil {
			return err
		}
	}
	if in.DisplayName != "" {
		if err := s.users.SetDisplayName(ctx, a.ID, in.DisplayName); err != nil {
			return err
		}
	}
	if !a.EmailVerified || a.Status == StatusPending {
		// The link reached the mailbox, which proves the address.
		if err := s.users.VerifyEmail(ctx, a.ID, s.clock.Now()); err != nil {
			return err
		}
	}
	if err := s.tenants.AddActiveMember(ctx, tenant.ID, a.ID); err != nil {
		return err
	}
	var p invitePayload
	if err := json.Unmarshal(t.Payload, &p); err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: decode invite")
	}
	if err := s.roles.GrantRoles(ctx, tenant.ID, a.ID, p.RoleIDs, &p.InvitedBy); err != nil {
		return err
	}
	return s.audit.Write(ctx, &AuditEvent{
		TenantID: tenant.ID, ActorID: a.ID, Action: ActionInviteAccepted,
		TargetType: TargetUser, TargetID: a.ID.String(),
		After: map[string]any{"role_ids": p.RoleIDs, "invited_by": p.InvitedBy.String()},
	})
}

// invitee loads the account and tenant of an invite token. An invite whose
// membership was removed since, or whose tenant is gone, is TOKEN_INVALID; a
// disabled account is ACCOUNT_DISABLED and a suspended tenant
// TENANT_SUSPENDED.
func (s *Invites) invitee(ctx context.Context, t *onetime.Token) (*Account, *TenantInfo, error) {
	if t.TenantID == nil {
		return nil, nil, apierr.New(apierr.ReasonTokenInvalid)
	}
	ms, err := s.tenants.Memberships(ctx, t.UserID)
	if err != nil {
		return nil, nil, err
	}
	var tenant *TenantInfo
	for i := range ms {
		if ms[i].Tenant.ID == *t.TenantID && (ms[i].Status == memberInvited || ms[i].Status == memberActive) {
			tenant = &ms[i].Tenant
		}
	}
	if tenant == nil {
		return nil, nil, apierr.New(apierr.ReasonTokenInvalid)
	}
	a, err := s.users.Get(ctx, t.UserID)
	if err != nil {
		return nil, nil, err
	}
	if a.Status == StatusDisabled {
		return nil, nil, apierr.New(apierr.ReasonAccountDisabled)
	}
	if !tenant.Active {
		return nil, nil, apierr.New(apierr.ReasonTenantSuspended)
	}
	return a, tenant, nil
}

// hasPassword reports whether the account has a password.
func (s *Invites) hasPassword(ctx context.Context, id uuid.UUID) (bool, error) {
	_, err := s.users.PasswordHash(ctx, id)
	if errors.Is(err, errorz.ErrNotFound) {
		return false, nil
	}
	return err == nil, err
}

// tokenError maps an unusable one-time token to TOKEN_INVALID and passes any
// other error through.
func tokenError(err error) error {
	if errors.Is(err, onetime.ErrInvalid) || errors.Is(err, onetime.ErrExpired) {
		return apierr.New(apierr.ReasonTokenInvalid)
	}
	return err
}

// maskEmail keeps the first character of the local part and the domain:
// bia@example.com becomes b**@example.com.
func maskEmail(email string) string {
	local, domain, ok := strings.Cut(email, "@")
	if !ok || local == "" {
		return "**"
	}
	first, _ := utf8.DecodeRuneInString(local)
	return string(first) + "**@" + domain
}

// Routes and the rate-limit key of the invite endpoints. Preview and accept
// are public and share the per-IP counter on the login budget, like reset.
const (
	invitePreviewPath = "/auth/invite/{token}"
	inviteAcceptPath  = "/auth/invite/accept"
	adminInvitePath   = "/users/invite"
	limitInviteIP     = "invite:ip:"
	// permUsersManage is the permission the admin invite needs; rbac owns
	// the catalog.
	permUsersManage = "users:manage"
)

// inviteUser answers POST /v1/admin/users/invite with 202.
//
//	@Summary     Invite a user
//	@Description Invites an email into the tenant with roles; re-inviting re-sends.
//	@Tags        admin
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.InviteRequest true "Request body"
//	@Security    BearerAuth
//	@Success     202 {object} response.BaseResponse[auth.InviteResponse]
//	@Failure     400 {object} response.BaseResponse[any] "Invalid body or unknown role"
//	@Failure     401 {object} response.BaseResponse[any] "Missing, invalid or expired token"
//	@Failure     403 {object} response.BaseResponse[any] "No users:manage, PERMISSION_NOT_HELD, SUPER_ADMIN_PROTECTED"
//	@Failure     409 {object} response.BaseResponse[any] "ALREADY_MEMBER: an active or disabled member"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/admin/users/invite [post]
func (m *Module) inviteUser(r *http.Request) (any, error) {
	var in InviteRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	if err := m.invites.Invite(r.Context(), &in); err != nil {
		return nil, err
	}
	return &response.Success{HTTPStatusCode: http.StatusAccepted, Data: InviteResponse{Status: memberInvited}}, nil
}

// previewInvite answers GET /v1/auth/invite/{token}.
//
//	@Summary     Preview an invite
//	@Description What an invite is for: tenant name, masked email, and whether a password is needed.
//	@Tags        auth
//	@Produce     json
//	@Param       token path string true "Invite token from the link"
//	@Success     200 {object} response.BaseResponse[auth.InvitePreviewResponse]
//	@Failure     400 {object} response.BaseResponse[any] "TOKEN_INVALID"
//	@Failure     403 {object} response.BaseResponse[any] "ACCOUNT_DISABLED or TENANT_SUSPENDED"
//	@Failure     429 {object} response.BaseResponse[any] "Rate limited"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/invite/{token} [get]
func (m *Module) previewInvite(r *http.Request) (any, error) {
	if err := m.limit(r, limitInviteIP, requestip.Get(r.Context())); err != nil {
		return nil, err
	}
	return m.invites.Preview(r.Context(), chi.URLParam(r, "token"))
}

// acceptInvite answers POST /v1/auth/invite/accept with a token response.
//
//	@Summary     Accept an invite
//	@Description Joins the tenant and signs in. password is required only when the account has none.
//	@Tags        auth
//	@Accept      json
//	@Produce     json
//	@Param       body body auth.AcceptInviteRequest true "Request body"
//	@Success     200 {object} response.BaseResponse[auth.TokenResponse]
//	@Failure     400 {object} response.BaseResponse[any] "TOKEN_INVALID or PASSWORD_POLICY"
//	@Failure     403 {object} response.BaseResponse[any] "ACCOUNT_DISABLED or TENANT_SUSPENDED"
//	@Failure     429 {object} response.BaseResponse[any] "Rate limited"
//	@Failure     500 {object} response.BaseResponse[any] "Internal error"
//	@Router      /v1/auth/invite/accept [post]
func (m *Module) acceptInvite(r *http.Request) (any, error) {
	if err := m.limit(r, limitInviteIP, requestip.Get(r.Context())); err != nil {
		return nil, err
	}
	var in AcceptInviteRequest
	if err := httpx.DecodeJSON(r, &in); err != nil {
		return nil, err
	}
	return m.invites.Accept(r.Context(), &in, device(r))
}
