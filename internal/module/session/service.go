package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/logger"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/clock"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/scope"
)

// tokenBytes is the entropy of a refresh token: 256 bits, opaque, not a JWT.
const tokenBytes = 32

// Rotation outcomes callers distinguish. They map to the API's refresh
// reasons: a reused token is an attack or a stale client, an expired one just
// needs a new sign-in.
var (
	// ErrReuse reports a token presented after it was already exchanged,
	// outside the grace window. The whole family is revoked.
	ErrReuse = errors.New("session: refresh token reused")
	// ErrExpired reports a token past its sliding or absolute expiry.
	ErrExpired = errors.New("session: refresh token expired")
	// ErrRevoked reports a token whose family was revoked.
	ErrRevoked = errors.New("session: refresh token revoked")
)

// Service issues and rotates refresh tokens. It owns the rotation
// transaction, because a rotation must lock its row whatever the caller does.
type Service struct {
	cfg   Config
	repo  *Repository
	db    *sqlkit.DB
	clock clock.Clock
	log   logger.Logger
	// audit records sign-outs from the session list; set by New.
	audit AuditWriter
	// members checks the target of an admin revoke; set by New.
	members Members
}

// NewService returns a Service. clk and log may be nil.
func NewService(cfg Config, repo *Repository, db *sqlkit.DB, clk clock.Clock, log logger.Logger) *Service {
	if clk == nil {
		clk = clock.System{}
	}
	if log == nil {
		log = logger.NewNoOp()
	}
	return &Service{cfg: cfg, repo: repo, db: db, clock: clk, log: log}
}

// Issue starts a new family, which is what a fresh sign-in does. The absolute
// expiry is fixed here and carried through every rotation, so a family cannot
// be extended indefinitely by refreshing.
func (s *Service) Issue(ctx context.Context, userID, tenantID uuid.UUID, d Device) (*Issued, error) {
	now := s.clock.Now()
	return s.issue(ctx, &Token{
		ID:                uuid.New(),
		FamilyID:          uuid.New(),
		UserID:            userID,
		TenantID:          tenantID,
		IssuedAt:          now,
		ExpiresAt:         now.Add(s.cfg.RefreshTTL),
		AbsoluteExpiresAt: now.Add(s.cfg.RefreshAbsoluteTTL),
		UserAgent:         d.UserAgent,
		IP:                nullable(d.IP),
	})
}

// Rotate exchanges a refresh token for the next one in its family.
//
// It runs in one leader transaction with the row locked, so two requests
// racing to rotate the same token are serialized. The rules, in order:
//
//   - a revoked token (its family was revoked) fails with ErrRevoked;
//   - a token rotated longer ago than the grace window is a reuse: the whole
//     family is revoked and ErrReuse is returned;
//   - a token rotated inside the grace window gets a sibling in the same
//     family, because several requests from one client often race across pods
//     and that is not an attack;
//   - an expired token, sliding or absolute, fails with ErrExpired;
//   - otherwise the token is marked rotated and the next one issued.
func (s *Service) Rotate(ctx context.Context, raw string, d Device) (*Issued, error) {
	var (
		issued *Issued
		// reuseFamily is set when the locked row turns out to be a replay.
		// The revocation cannot happen inside the transaction below,
		// because that transaction rolls back when Rotate fails, which
		// would undo it; it is applied afterwards instead.
		reuseFamily uuid.UUID
	)
	err := database.WithTx(ctx, s.db, func(ctx context.Context) error {
		current, err := s.repo.LockByHash(ctx, hashToken(raw))
		if err != nil {
			return err
		}
		next, err := s.rotateLocked(ctx, current, d)
		if err != nil {
			if errors.Is(err, ErrReuse) {
				reuseFamily = current.FamilyID
			}
			return err
		}
		issued = next
		return nil
	})
	if reuseFamily != uuid.Nil {
		s.revokeReusedFamily(ctx, reuseFamily)
	}
	if err != nil {
		return nil, err
	}
	return issued, nil
}

// revokeReusedFamily revokes a family whose token was replayed, in its own
// transaction so it survives the failed rotation. A revocation that cannot be
// written is logged rather than returned: the caller is already being denied,
// and hiding the denial behind an internal error would help an attacker.
func (s *Service) revokeReusedFamily(ctx context.Context, familyID uuid.UUID) {
	n, err := s.repo.RevokeFamily(ctx, familyID, s.clock.Now())
	if err != nil {
		s.log.ErrorWithContext(ctx, "could not revoke a reused token family",
			logger.F("family_id", familyID.String()), logger.F("error", err.Error()))
		return
	}
	s.log.WarnWithContext(ctx, "refresh token reuse detected, family revoked",
		logger.F("family_id", familyID.String()), logger.F("tokens_revoked", n))
}

// rotateLocked applies the rotation rules to a locked row.
func (s *Service) rotateLocked(ctx context.Context, current *Token, d Device) (*Issued, error) {
	now := s.clock.Now()

	if current.Revoked() {
		return nil, errorz.Wrap(ErrRevoked).WithCode(errorz.CodeUnauthorized).WithMessage(ErrRevoked.Error())
	}
	if current.Rotated() {
		return s.handleRotated(ctx, current, d, now)
	}
	if now.After(current.ExpiresAt) || now.After(current.AbsoluteExpiresAt) {
		return nil, errorz.Wrap(ErrExpired).WithCode(errorz.CodeUnauthorized).WithMessage(ErrExpired.Error())
	}
	if err := s.repo.MarkRotated(ctx, current.ID, now); err != nil {
		return nil, err
	}
	return s.issueNext(ctx, current, d, now)
}

// handleRotated decides whether an already-exchanged token is a concurrent
// refresh or a replay. The family revocation that follows a replay is applied
// by Rotate, outside this transaction.
func (s *Service) handleRotated(ctx context.Context, current *Token, d Device, now time.Time) (*Issued, error) {
	if now.Sub(*current.RotatedAt) <= s.cfg.RefreshReuseGrace {
		// A race, not an attack: hand out a sibling in the same family.
		return s.issueNext(ctx, current, d, now)
	}
	return nil, errorz.Wrap(ErrReuse).WithCode(errorz.CodeUnauthorized).WithMessage(ErrReuse.Error())
}

// issueNext issues the next token of an existing family, sliding the expiry
// forward but keeping the family's absolute deadline.
func (s *Service) issueNext(ctx context.Context, current *Token, d Device, now time.Time) (*Issued, error) {
	return s.issue(ctx, &Token{
		ID:                uuid.New(),
		FamilyID:          current.FamilyID,
		UserID:            current.UserID,
		TenantID:          current.TenantID,
		IssuedAt:          now,
		ExpiresAt:         now.Add(s.cfg.RefreshTTL),
		AbsoluteExpiresAt: current.AbsoluteExpiresAt,
		UserAgent:         d.UserAgent,
		IP:                nullable(d.IP),
	})
}

// issue generates the raw token, stores its hash and returns both.
func (s *Service) issue(ctx context.Context, t *Token) (*Issued, error) {
	raw, err := newRawToken()
	if err != nil {
		return nil, err
	}
	if err := s.repo.Insert(ctx, t, hashToken(raw)); err != nil {
		return nil, err
	}
	return &Issued{Raw: raw, Token: t}, nil
}

// Lookup returns the token behind a raw value in whatever state it is, or an
// errorz.NotFound error. Sign-out uses it to find the family and the user.
func (s *Service) Lookup(ctx context.Context, raw string) (*Token, error) {
	return s.repo.ByHash(ctx, hashToken(raw))
}

// Exchangeable reports whether t could still be exchanged now: not revoked,
// within its sliding and absolute expiry, and either never rotated or rotated
// inside the grace window. It is the same test Rotate applies, without the
// side effects.
func (s *Service) Exchangeable(t *Token) bool {
	now := s.clock.Now()
	if t.Revoked() || now.After(t.ExpiresAt) || now.After(t.AbsoluteExpiresAt) {
		return false
	}
	return !t.Rotated() || now.Sub(*t.RotatedAt) <= s.cfg.RefreshReuseGrace
}

// RevokeFamily revokes one chain of tokens, which is what signing out of a
// single device does.
func (s *Service) RevokeFamily(ctx context.Context, familyID uuid.UUID) error {
	_, err := s.repo.RevokeFamily(ctx, familyID, s.clock.Now())
	return err
}

// RevokeAllForUser revokes every live token of a user: logout-all, a password
// reset, or an account being disabled.
func (s *Service) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return s.repo.RevokeAllForUser(ctx, userID, s.clock.Now())
}

// RevokeSession revokes one of the user's sessions (a family), so that
// device cannot refresh again. A family that is not the user's, or has no
// live token left, is an errorz.NotFound error, so IDs cannot be probed.
func (s *Service) RevokeSession(ctx context.Context, userID, familyID uuid.UUID) error {
	n, err := s.repo.RevokeUserFamily(ctx, userID, familyID, s.clock.Now())
	if err != nil {
		return err
	}
	if n == 0 {
		return errorz.NotFound().WithMessage("session: not found")
	}
	return nil
}

// SignOutDevice revokes one of the user's sessions from the session list and
// audits it as a logout, in one transaction.
func (s *Service) SignOutDevice(ctx context.Context, userID, tenantID, familyID uuid.UUID) error {
	return database.WithTx(ctx, s.db, func(ctx context.Context) error {
		if err := s.RevokeSession(ctx, userID, familyID); err != nil {
			return err
		}
		return s.audit.Write(ctx, &AuditEvent{
			TenantID: tenantID, ActorID: userID, Action: ActionLogout,
			TargetType: "user", TargetID: userID.String(),
			After: map[string]any{"family_id": familyID.String(), "via": "session_list"},
		})
	})
}

// RevokeForMember signs a member of the caller's tenant out of every device
// in that tenant, so role changes take effect before the access token
// expires. Sessions in the user's other tenants are left alone. A user who
// is not a member is 404.
func (s *Service) RevokeForMember(ctx context.Context, userID uuid.UUID) error {
	actorID, err := scope.User(ctx)
	if err != nil {
		return err
	}
	tenantID, err := scope.Tenant(ctx)
	if err != nil {
		return err
	}
	member, err := s.members.IsMember(ctx, tenantID, userID)
	if err != nil {
		return err
	}
	if !member {
		return errorz.NotFound().WithMessage("session: user not found")
	}
	return database.WithTx(ctx, s.db, func(ctx context.Context) error {
		n, err := s.repo.RevokeAllForUserInTenant(ctx, userID, tenantID, s.clock.Now())
		if err != nil {
			return err
		}
		return s.audit.Write(ctx, &AuditEvent{
			TenantID: tenantID, ActorID: actorID, Action: ActionSessionsRevoke,
			TargetType: "user", TargetID: userID.String(),
			After: map[string]any{"revoked_tokens": n},
		})
	})
}

// List returns the user's live sessions, one per device.
func (s *Service) List(ctx context.Context, userID uuid.UUID) ([]Session, error) {
	return s.repo.ListSessions(ctx, userID, s.clock.Now())
}

// newRawToken generates 256 bits of randomness, base64url encoded.
func newRawToken() (string, error) {
	b := make([]byte, tokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("session: generate token")
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashToken is the stored form of a refresh token. Only the hash is kept, so
// a database leak does not yield usable tokens.
func hashToken(raw string) []byte {
	sum := sha256.Sum256([]byte(raw))
	return sum[:]
}

// nullable maps an empty string to NULL, so an absent IP is not stored as
// text an inet column would reject.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
