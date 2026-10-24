package auth

import (
	"context"
	"errors"
	"slices"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/clock"
)

// limitRefreshIP is the rate-limit key prefix of POST /v1/auth/refresh.
const limitRefreshIP = "refresh:ip:"

// Refreshes runs the refresh-token endpoints: refresh with rotation, logout
// and logout-all. The rotation rules (grace window, reuse detection, expiry)
// belong to the session module behind the Sessions port; this layer re-reads
// the account and the tenant on every refresh and signs the new access token.
type Refreshes struct {
	tx       txFunc
	v        validator.Validator
	users    Users
	tenants  Tenants
	sessions Sessions
	audit    AuditWriter
	limiter  Limiter
	issue    *tokenIssuer
	clock    clock.Clock
	log      logger.Logger
}

// Refresh exchanges a refresh token for a new token response (APP_FLOW 7).
//
// The account's status, its membership and the tenant are read again, and
// the access token carries the roles the user holds now, so an admin's
// change takes effect here. An account that may no longer refresh loses the
// whole family; that revocation is committed (no transaction is open here)
// before the error is returned.
func (s *Refreshes) Refresh(ctx context.Context, in *RefreshRequest, d Device) (*TokenResponse, error) {
	if err := s.limit(ctx, limitRefreshIP, d.IP); err != nil {
		return nil, err
	}
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	issued, err := s.sessions.Rotate(ctx, in.RefreshToken, d)
	if err != nil {
		return nil, s.rotateFailed(ctx, in.RefreshToken, err)
	}
	a, tenant, err := s.recheck(ctx, issued)
	if err != nil {
		if apierr.ReasonOf(err) == "" {
			return nil, err
		}
		return nil, s.revokeAndFail(ctx, issued.FamilyID, err)
	}
	return s.issue.session(ctx, a, tenant, issued)
}

// limit checks one rate-limit key; an empty value (no client IP) is skipped.
func (s *Refreshes) limit(ctx context.Context, prefix, value string) error {
	if s.limiter == nil || value == "" {
		return nil
	}
	return s.limiter.Check(ctx, prefix+value)
}

// rotateFailed maps a failed rotation to its reason. A replayed or revoked
// token is REFRESH_REUSED and audited; the session module has already
// committed the family's revocation.
func (s *Refreshes) rotateFailed(ctx context.Context, raw string, err error) error {
	switch {
	case errors.Is(err, errorz.ErrNotFound):
		return apierr.New(apierr.ReasonInvalidCredentials)
	case errors.Is(err, ErrRefreshExpired):
		return apierr.New(apierr.ReasonRefreshExpired)
	case errors.Is(err, ErrRefreshReused), errors.Is(err, ErrRefreshRevoked):
		s.auditReuse(ctx, raw, errors.Is(err, ErrRefreshReused))
		return apierr.New(apierr.ReasonRefreshReused)
	default:
		return err
	}
}

// auditReuse records a replayed refresh token against its owner. It runs
// after the request is already denied, so a failure is logged, not returned.
func (s *Refreshes) auditReuse(ctx context.Context, raw string, rotated bool) {
	t, err := s.sessions.Lookup(ctx, raw)
	if err == nil {
		err = s.audit.Write(ctx, &AuditEvent{
			TenantID: t.TenantID, ActorID: t.UserID, Action: ActionRefreshReuse,
			TargetType: TargetUser, TargetID: t.UserID.String(),
			After: map[string]any{"family_id": t.FamilyID.String(), "rotated": rotated},
		})
	}
	if err != nil {
		s.log.ErrorWithContext(ctx, "could not audit a refresh token reuse", logger.F("error", err.Error()))
	}
}

// recheck reads the account and the tenant the refreshed family belongs to
// and refuses one that may no longer act there. A refusal carries an
// apierr reason; any other error is a failure to read.
func (s *Refreshes) recheck(ctx context.Context, issued *IssuedSession) (*Account, *TenantInfo, error) {
	a, err := s.users.Get(ctx, issued.UserID)
	if errors.Is(err, errorz.ErrNotFound) {
		return nil, nil, apierr.New(apierr.ReasonInvalidCredentials)
	}
	if err != nil {
		return nil, nil, err
	}
	if a.Status != StatusActive {
		return nil, nil, apierr.New(apierr.ReasonAccountDisabled)
	}
	if a.MustChangePassword {
		// A forced password change ends the session instead of trading it
		// for the restricted token: that token changes the password without
		// the current one, and a refresh token never proved the password.
		// The user signs in again to get it.
		return nil, nil, apierr.New(apierr.ReasonPasswordChangeRequired)
	}
	tenant, err := s.tenants.Tenant(ctx, issued.TenantID)
	if errors.Is(err, errorz.ErrNotFound) {
		return nil, nil, apierr.New(apierr.ReasonInvalidCredentials)
	}
	if err != nil {
		return nil, nil, err
	}
	if a.IsSuperAdmin {
		// The super admin may act in any tenant, suspended or not.
		return a, tenant, nil
	}
	if !tenant.Active {
		return nil, nil, apierr.New(apierr.ReasonTenantSuspended)
	}
	member, err := s.isActiveMember(ctx, a.ID, tenant.ID)
	if err != nil {
		return nil, nil, err
	}
	if !member {
		return nil, nil, apierr.New(apierr.ReasonInvalidCredentials)
	}
	return a, tenant, nil
}

// isActiveMember reports whether userID is an active member of tenantID.
func (s *Refreshes) isActiveMember(ctx context.Context, userID, tenantID uuid.UUID) (bool, error) {
	all, err := s.tenants.Memberships(ctx, userID)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(all, func(m Membership) bool {
		return m.Active && m.Tenant.ID == tenantID
	}), nil
}

// revokeAndFail revokes the family of an account that may no longer refresh,
// committed on its own, then returns the refusal.
func (s *Refreshes) revokeAndFail(ctx context.Context, familyID uuid.UUID, refusal error) error {
	if err := s.sessions.RevokeFamily(ctx, familyID); err != nil {
		return err
	}
	s.log.InfoWithContext(ctx, "refresh refused, family revoked",
		logger.F("family_id", familyID.String()), logger.F("reason", string(apierr.ReasonOf(refusal))))
	return refusal
}

// Logout revokes the family of the presented refresh token: this device is
// signed out. An unknown or already dead token is a silent no-op (TRD 9.4).
func (s *Refreshes) Logout(ctx context.Context, in *RefreshRequest) error {
	t, err := s.live(ctx, in)
	if err != nil || t == nil {
		return err
	}
	return s.tx(ctx, func(ctx context.Context) error {
		if err := s.sessions.RevokeFamily(ctx, t.FamilyID); err != nil {
			return err
		}
		return s.audit.Write(ctx, &AuditEvent{
			TenantID: t.TenantID, ActorID: t.UserID, Action: ActionLogout,
			TargetType: TargetUser, TargetID: t.UserID.String(),
			After: map[string]any{"family_id": t.FamilyID.String()},
		})
	})
}

// LogoutAll revokes every family of the presented refresh token's owner:
// every device is signed out. An unknown or already dead token is a silent
// no-op (TRD 9.4).
func (s *Refreshes) LogoutAll(ctx context.Context, in *RefreshRequest) error {
	t, err := s.live(ctx, in)
	if err != nil || t == nil {
		return err
	}
	return s.tx(ctx, func(ctx context.Context) error {
		if err := s.sessions.RevokeAllForUser(ctx, t.UserID); err != nil {
			return err
		}
		return s.audit.Write(ctx, &AuditEvent{
			TenantID: t.TenantID, ActorID: t.UserID, Action: ActionLogoutAll,
			TargetType: TargetUser, TargetID: t.UserID.String(),
		})
	})
}

// live validates the body and returns the presented token when it could
// still be exchanged, or nil when it is unknown, revoked, expired or rotated
// longer ago than the reuse grace. Only a token that could refresh may sign
// anyone out: its holder already controls the session, while a dead token
// (a stolen one whose family was revoked, an old one left in storage) must
// not be able to end the owner's other sessions.
func (s *Refreshes) live(ctx context.Context, in *RefreshRequest) (*SessionToken, error) {
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	t, err := s.sessions.Lookup(ctx, in.RefreshToken)
	if errors.Is(err, errorz.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !t.Exchangeable {
		return nil, nil
	}
	return t, nil
}
