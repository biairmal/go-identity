package tenant

import (
	"context"
	"errors"
	"testing"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// recordingAudit captures the events the service writes, standing in for the
// audit module. A small fake beats a mock for a module's own port.
type recordingAudit struct {
	events []*AuditEvent
	err    error
}

func (a *recordingAudit) Write(_ context.Context, e *AuditEvent) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, e)
	return nil
}

// newService builds a service over db with a recording audit writer.
func newService(db *sqlkit.DB, cfg Config) (*Service, *recordingAudit) {
	rec := &recordingAudit{}
	return NewService(cfg, NewRepository(db), rec, nil), rec
}

// TestEnsureDefaultIsIdempotent is the acceptance criterion for T2.4:
// starting twice must leave exactly one default tenant, because EnsureDefault
// runs on every start and on every pod.
func TestEnsureDefaultIsIdempotent(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	cfg := Default()
	svc, rec := newService(db, cfg)

	first, err := svc.EnsureDefault(ctx)
	if err != nil {
		t.Fatalf("first EnsureDefault() = %v", err)
	}
	if first.Slug != cfg.DefaultTenantSlug || !first.Active() {
		t.Fatalf("created tenant = %+v, want slug %q and active", first, cfg.DefaultTenantSlug)
	}

	second, err := svc.EnsureDefault(ctx)
	if err != nil {
		t.Fatalf("second EnsureDefault() = %v", err)
	}
	if second.ID != first.ID {
		t.Errorf("second EnsureDefault() returned %v, want the existing %v", second.ID, first.ID)
	}
	if n := countTenants(ctx, t, db); n != 1 {
		t.Errorf("after two starts: %d tenants, want 1", n)
	}

	// Only the creation is audited, so a restart does not fill the log.
	if len(rec.events) != 1 {
		t.Fatalf("got %d audit events, want 1 for the creation only", len(rec.events))
	}
	if rec.events[0].Action != ActionTenantCreate {
		t.Errorf("audit action = %q, want %q", rec.events[0].Action, ActionTenantCreate)
	}
}

// TestEnsureDefaultHonoursTheConfiguredSlug checks the slug comes from the
// module's config, not a constant.
func TestEnsureDefaultHonoursTheConfiguredSlug(t *testing.T) {
	db := testkit.Postgres(t)
	cfg := Default()
	cfg.DefaultTenantSlug = "acme-corp"
	svc, _ := newService(db, cfg)

	got, err := svc.EnsureDefault(context.Background())
	if err != nil {
		t.Fatalf("EnsureDefault() = %v", err)
	}
	if got.Slug != "acme-corp" {
		t.Errorf("slug = %q, want acme-corp", got.Slug)
	}
}

// TestEnsureDefaultRollsBackWithTheAudit checks the creation and its audit
// row share one transaction: when the audit write fails, no tenant is left.
func TestEnsureDefaultRollsBackWithTheAudit(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	rec := &recordingAudit{err: errors.New("audit unavailable")}
	svc := NewService(Default(), NewRepository(db), rec, nil)

	err := database.WithTx(ctx, db, func(ctx context.Context) error {
		_, err := svc.EnsureDefault(ctx)
		return err
	})
	if err == nil {
		t.Fatal("EnsureDefault() = nil, want the audit error")
	}
	if n := countTenants(ctx, t, db); n != 0 {
		t.Errorf("after a failed audit write: %d tenants, want 0", n)
	}
}

// TestMembership covers adding a member, reading it back and changing status.
func TestMembership(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	svc, rec := newService(db, Default())
	repo := NewRepository(db)

	tn, err := svc.EnsureDefault(ctx)
	if err != nil {
		t.Fatalf("EnsureDefault() = %v", err)
	}
	userID := insertUser(ctx, t, db, "member@example.com")

	if err := svc.AddMember(ctx, tn.ID, userID, MemberInvited); err != nil {
		t.Fatalf("AddMember() = %v", err)
	}
	m, err := svc.Member(ctx, tn.ID, userID)
	if err != nil {
		t.Fatalf("Member() = %v", err)
	}
	if m.Status != MemberInvited || m.Active() {
		t.Errorf("membership = %+v, want invited and not active", m)
	}
	if m.JoinedAt != nil {
		t.Error("an invited membership should have no joined_at")
	}

	// Adding the same member twice is not an error and does not duplicate.
	if err := svc.AddMember(ctx, tn.ID, userID, MemberInvited); err != nil {
		t.Fatalf("second AddMember() = %v", err)
	}

	if err := repo.SetMemberStatus(ctx, tn.ID, userID, MemberActive); err != nil {
		t.Fatalf("SetMemberStatus() = %v", err)
	}
	m, err = svc.Member(ctx, tn.ID, userID)
	if err != nil {
		t.Fatalf("Member() after activation = %v", err)
	}
	if !m.Active() || m.JoinedAt == nil {
		t.Errorf("membership = %+v, want active with a joined_at", m)
	}

	memberships, err := svc.MembershipsOf(ctx, userID)
	if err != nil {
		t.Fatalf("MembershipsOf() = %v", err)
	}
	if len(memberships) != 1 || memberships[0].TenantID != tn.ID {
		t.Fatalf("MembershipsOf() = %+v, want the one tenant", memberships)
	}
	if memberships[0].Slug != tn.Slug || memberships[0].MemberStatus != MemberActive {
		t.Errorf("membership view = %+v, want the tenant slug and the active status", memberships[0])
	}

	if len(rec.events) < 2 {
		t.Errorf("got %d audit events, want the tenant creation and the member add", len(rec.events))
	}
}

// TestMemberNotFound checks a missing membership is a not-found error, which
// keeps other tenants' IDs unprobeable.
func TestMemberNotFound(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	svc, _ := newService(db, Default())

	tn, err := svc.EnsureDefault(ctx)
	if err != nil {
		t.Fatalf("EnsureDefault() = %v", err)
	}
	_, err = svc.Member(ctx, tn.ID, uuid.New())
	if !errors.Is(err, errorz.ErrNotFound) {
		t.Fatalf("Member() for a stranger = %v, want not found", err)
	}
	if err := NewRepository(db).SetMemberStatus(ctx, tn.ID, uuid.New(), MemberActive); !errors.Is(
		err, errorz.ErrNotFound) {
		t.Fatalf("SetMemberStatus() for a stranger = %v, want not found", err)
	}
}

// TestSetStatusChecksTheVersion covers the optimistic locking on tenants: a
// stale version is a conflict, not a silent overwrite.
func TestSetStatusChecksTheVersion(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	svc, _ := newService(db, Default())
	repo := NewRepository(db)

	tn, err := svc.EnsureDefault(ctx)
	if err != nil {
		t.Fatalf("EnsureDefault() = %v", err)
	}

	if err := repo.SetStatus(ctx, tn.ID, tn.Version, StatusSuspended); err != nil {
		t.Fatalf("SetStatus() = %v", err)
	}
	after, err := repo.ByID(ctx, tn.ID)
	if err != nil {
		t.Fatalf("ByID() = %v", err)
	}
	if after.Active() || after.Version != tn.Version+1 {
		t.Errorf("tenant = %+v, want suspended with a bumped version", after)
	}

	// The original version is now stale.
	err = repo.SetStatus(ctx, tn.ID, tn.Version, StatusActive)
	if !errors.Is(err, errorz.ErrConflict) {
		t.Fatalf("SetStatus() with a stale version = %v, want a conflict", err)
	}

	// A missing tenant is not found, whatever the version.
	err = repo.SetStatus(ctx, uuid.New(), 1, StatusActive)
	if !errors.Is(err, errorz.ErrNotFound) {
		t.Fatalf("SetStatus() on a missing tenant = %v, want not found", err)
	}
}

// TestListReturnsEveryTenant checks the listing internal/app uses to seed
// roles into each tenant.
func TestListReturnsEveryTenant(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	repo := NewRepository(db)
	svc, _ := newService(db, Default())

	if _, err := svc.EnsureDefault(ctx); err != nil {
		t.Fatalf("EnsureDefault() = %v", err)
	}
	if _, _, err := repo.EnsureBySlug(ctx, "second-tenant", "Second"); err != nil {
		t.Fatalf("EnsureBySlug() = %v", err)
	}

	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("List() = %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List() returned %d tenants, want 2", len(list))
	}
}

// countTenants returns how many tenant rows exist.
func countTenants(ctx context.Context, t *testing.T, db *sqlkit.DB) int {
	t.Helper()
	var n int
	if err := db.Leader().QueryRowContext(ctx, `SELECT count(*) FROM tenants`).Scan(&n); err != nil {
		t.Fatalf("count tenants: %v", err)
	}
	return n
}

// insertUser creates a user row directly: the user module and its email
// encryption arrive in T3.2, and these tests only need a valid foreign key.
func insertUser(ctx context.Context, t *testing.T, db *sqlkit.DB, label string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.Leader().QueryRowContext(ctx,
		`INSERT INTO users (email_enc, email_hash) VALUES ($1, $2) RETURNING id`,
		[]byte("enc:"+label), []byte("hash:"+label)).Scan(&id)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	return id
}

// TestEnsureActiveMember covers the three starting points: no membership
// (added and audited), an invited one (activated and audited) and an active
// one (left alone, no audit row).
func TestEnsureActiveMember(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	svc, rec := newService(db, Default())
	tn, err := svc.EnsureDefault(ctx)
	if err != nil {
		t.Fatalf("EnsureDefault() = %v", err)
	}
	fresh := insertUser(ctx, t, db, "fresh@example.com")
	invited := insertUser(ctx, t, db, "invited@example.com")
	if err := svc.AddMember(ctx, tn.ID, invited, MemberInvited); err != nil {
		t.Fatalf("AddMember() = %v", err)
	}

	for _, id := range []uuid.UUID{fresh, invited} {
		before := len(rec.events)
		if err := svc.EnsureActiveMember(ctx, tn.ID, id); err != nil {
			t.Fatalf("EnsureActiveMember() = %v", err)
		}
		m, err := svc.Member(ctx, tn.ID, id)
		if err != nil {
			t.Fatalf("Member() = %v", err)
		}
		if !m.Active() || m.JoinedAt == nil {
			t.Errorf("membership = %+v, want active with a joined_at", m)
		}
		if len(rec.events) != before+1 || rec.events[len(rec.events)-1].Action != ActionMemberAdd {
			t.Errorf("want one %s audit event for the change", ActionMemberAdd)
		}
	}

	before := len(rec.events)
	if err := svc.EnsureActiveMember(ctx, tn.ID, fresh); err != nil {
		t.Fatalf("EnsureActiveMember() on an active member = %v", err)
	}
	if len(rec.events) != before {
		t.Error("an already active membership was audited again")
	}
}
