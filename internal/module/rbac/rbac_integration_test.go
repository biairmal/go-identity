package rbac

import (
	"context"
	"errors"
	"slices"
	"testing"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// recordingAudit captures the events the service writes.
type recordingAudit struct{ events []*AuditEvent }

func (a *recordingAudit) Write(_ context.Context, e *AuditEvent) error {
	a.events = append(a.events, e)
	return nil
}

// testConfig is a catalog and two roles, like a client's configuration.
func testConfig() Config {
	cfg := Default()
	cfg.Permissions = []Permission{
		{Key: "notes:read", Description: "Read notes"},
		{Key: "notes:write", Description: "Write notes"},
		{Key: "notes:read:any", Description: "Read anyone's notes"},
	}
	cfg.Roles = map[string][]string{
		"admin":  {PermUsersRead, PermUsersManage, PermRolesManage, "notes:read:any"},
		"member": {"notes:read", "notes:write"},
	}
	return cfg
}

// newService builds a service over db with a recording audit writer.
func newService(db *sqlkit.DB, cfg Config) (*Service, *recordingAudit) {
	rec := &recordingAudit{}
	return NewService(cfg, NewRepository(db), rec, nil), rec
}

// TestSyncCatalogAddsConfiguredAndSystemKeys checks the catalog holds both
// what the client configured and the permissions identity itself checks.
func TestSyncCatalogAddsConfiguredAndSystemKeys(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	cfg := testConfig()
	// A client may list a system key to describe it; it stays a system key.
	cfg.Permissions = append(cfg.Permissions, Permission{Key: PermUsersRead, Description: "See people"})
	svc, _ := newService(db, cfg)

	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}
	got, err := svc.Permissions(ctx)
	if err != nil {
		t.Fatalf("Permissions() = %v", err)
	}

	byKey := map[string]CatalogEntry{}
	for _, e := range got {
		byKey[e.Key] = e
	}
	for _, key := range []string{"notes:read", "notes:write", "notes:read:any"} {
		if _, ok := byKey[key]; !ok {
			t.Errorf("configured key %q missing from the catalog", key)
		}
		if byKey[key].IsSystem {
			t.Errorf("configured key %q marked as a system permission", key)
		}
	}
	for _, p := range SystemPermissions() {
		e, ok := byKey[p.Key]
		if !ok {
			t.Errorf("system key %q missing from the catalog", p.Key)
			continue
		}
		if !e.IsSystem {
			t.Errorf("system key %q not marked as a system permission", p.Key)
		}
	}
	if d := byKey[PermUsersRead].Description; d != "See people" {
		t.Errorf("configured description of a system key = %q, want the configured one", d)
	}
}

// TestSyncCatalogIsIdempotentAndUpdatesDescriptions checks a second start
// changes nothing but the descriptions, and never deletes a key.
func TestSyncCatalogIsIdempotentAndUpdatesDescriptions(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	cfg := testConfig()
	svc, _ := newService(db, cfg)

	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("first SyncCatalog() = %v", err)
	}
	first, err := svc.Permissions(ctx)
	if err != nil {
		t.Fatalf("Permissions() = %v", err)
	}

	// The description changes; the key set does not.
	cfg.Permissions[0].Description = "Read every note"
	svc2, _ := newService(db, cfg)
	if err := svc2.SyncCatalog(ctx); err != nil {
		t.Fatalf("second SyncCatalog() = %v", err)
	}
	second, err := svc2.Permissions(ctx)
	if err != nil {
		t.Fatalf("Permissions() = %v", err)
	}
	if len(first) != len(second) {
		t.Fatalf("catalog grew from %d to %d keys over a restart", len(first), len(second))
	}
	for _, e := range second {
		if e.Key == "notes:read" && e.Description != "Read every note" {
			t.Errorf("description = %q, want the updated text", e.Description)
		}
	}
}

// TestSyncCatalogKeepsGrantedKeysOutOfTheConfig is the rule that protects a
// role: a key a role still grants is never deleted, only warned about.
func TestSyncCatalogKeepsGrantedKeysOutOfTheConfig(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	repo := NewRepository(db)
	tenantID := insertTenant(ctx, t, db, "keeps-keys")

	svc, _ := newService(db, testConfig())
	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}
	if err := svc.SeedTenant(ctx, tenantID); err != nil {
		t.Fatalf("SeedTenant() = %v", err)
	}

	// Drop notes:write from the configuration and sync again.
	narrowed := testConfig()
	narrowed.Permissions = []Permission{{Key: "notes:read"}, {Key: "notes:read:any"}}
	narrowed.Roles = map[string][]string{}
	svc2, _ := newService(db, narrowed)
	if err := svc2.SyncCatalog(ctx); err != nil {
		t.Fatalf("second SyncCatalog() = %v", err)
	}

	member, err := repo.RoleByName(ctx, &tenantID, "member")
	if err != nil {
		t.Fatalf("RoleByName() = %v", err)
	}
	keys, err := repo.RolePermissions(ctx, member.ID)
	if err != nil {
		t.Fatalf("RolePermissions() = %v", err)
	}
	if !slices.Contains(keys, "notes:write") {
		t.Errorf("member grants = %v, want notes:write kept even though the config dropped it", keys)
	}
}

// TestSeedTenantDoesNotOverwriteAdminEdits is the acceptance criterion: a
// restart after an admin edited a seeded role leaves the edit alone.
func TestSeedTenantDoesNotOverwriteAdminEdits(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	repo := NewRepository(db)
	tenantID := insertTenant(ctx, t, db, "admin-edits")
	svc, _ := newService(db, testConfig())

	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}
	if err := svc.SeedTenant(ctx, tenantID); err != nil {
		t.Fatalf("first SeedTenant() = %v", err)
	}

	member, err := repo.RoleByName(ctx, &tenantID, "member")
	if err != nil {
		t.Fatalf("RoleByName() = %v", err)
	}
	// The admin narrows the role to read-only.
	if err := repo.SetRolePermissions(ctx, member.ID, []string{"notes:read"}); err != nil {
		t.Fatalf("SetRolePermissions() = %v", err)
	}

	// A restart must not put notes:write back.
	if err := svc.SeedTenant(ctx, tenantID); err != nil {
		t.Fatalf("second SeedTenant() = %v", err)
	}
	keys, err := repo.RolePermissions(ctx, member.ID)
	if err != nil {
		t.Fatalf("RolePermissions() = %v", err)
	}
	if len(keys) != 1 || keys[0] != "notes:read" {
		t.Errorf("member grants after a restart = %v, want the admin's [notes:read]", keys)
	}

	// And it does not duplicate the roles either.
	roles, err := repo.RolesIn(ctx, &tenantID)
	if err != nil {
		t.Fatalf("RolesIn() = %v", err)
	}
	if len(roles) != 2 {
		t.Errorf("tenant has %d roles after two seedings, want 2", len(roles))
	}
}

// TestSeedTenantOffByConfig checks seed_on_start: false creates nothing.
func TestSeedTenantOffByConfig(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	cfg := testConfig()
	cfg.SeedOnStart = false
	svc, _ := newService(db, cfg)
	tenantID := insertTenant(ctx, t, db, "no-seeding")

	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}
	if err := svc.SeedTenant(ctx, tenantID); err != nil {
		t.Fatalf("SeedTenant() = %v", err)
	}
	roles, err := NewRepository(db).RolesIn(ctx, &tenantID)
	if err != nil {
		t.Fatalf("RolesIn() = %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("seeding is off but the tenant has %d roles", len(roles))
	}
}

// TestEffectivePermissionsIsTheUnion is the other acceptance criterion: a
// user with two roles holds the union of their permissions, with no repeats.
func TestEffectivePermissionsIsTheUnion(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	repo := NewRepository(db)
	svc, rec := newService(db, testConfig())

	tenantID := insertTenant(ctx, t, db, "union")
	userID := insertMember(ctx, t, db, tenantID, "union@example.com")
	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}
	if err := svc.SeedTenant(ctx, tenantID); err != nil {
		t.Fatalf("SeedTenant() = %v", err)
	}

	admin, err := repo.RoleByName(ctx, &tenantID, "admin")
	if err != nil {
		t.Fatalf("RoleByName(admin) = %v", err)
	}
	member, err := repo.RoleByName(ctx, &tenantID, "member")
	if err != nil {
		t.Fatalf("RoleByName(member) = %v", err)
	}

	err = svc.AssignRoles(ctx, tenantID, userID, []uuid.UUID{admin.ID, member.ID}, nil)
	if err != nil {
		t.Fatalf("AssignRoles() = %v", err)
	}

	got, err := svc.EffectivePermissions(ctx, tenantID, userID)
	if err != nil {
		t.Fatalf("EffectivePermissions() = %v", err)
	}
	want := []string{
		"notes:read", "notes:read:any", "notes:write",
		PermRolesManage, PermUsersManage, PermUsersRead,
	}
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("EffectivePermissions() = %v, want the union %v", got, want)
	}

	names, err := svc.RoleNames(ctx, tenantID, userID)
	if err != nil {
		t.Fatalf("RoleNames() = %v", err)
	}
	if !slices.Equal(names, []string{"admin", "member"}) {
		t.Errorf("RoleNames() = %v, want [admin member]", names)
	}
	if len(rec.events) != 1 || rec.events[0].Action != ActionUserRolesAssigned {
		t.Errorf("audit events = %+v, want one assignment event", rec.events)
	}
}

// TestAssignRoleRejectsAnotherTenantsRole checks the composite foreign key
// surfaces as an error through the service too.
func TestAssignRoleRejectsAnotherTenantsRole(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	repo := NewRepository(db)
	svc, _ := newService(db, testConfig())

	tenantA := insertTenant(ctx, t, db, "tenant-a")
	tenantB := insertTenant(ctx, t, db, "tenant-b")
	userID := insertMember(ctx, t, db, tenantB, "cross@example.com")

	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}
	if err := svc.SeedTenant(ctx, tenantA); err != nil {
		t.Fatalf("SeedTenant() = %v", err)
	}
	roleInA, err := repo.RoleByName(ctx, &tenantA, "admin")
	if err != nil {
		t.Fatalf("RoleByName() = %v", err)
	}

	err = repo.AssignRole(ctx, tenantB, userID, roleInA.ID, nil)
	if err == nil {
		t.Fatal("AssignRole() across tenants = nil, want an error")
	}
}

// TestTenantRoleMap checks the map served to resource services, including a
// role with no permissions.
func TestTenantRoleMap(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	cfg := testConfig()
	cfg.Roles["observer"] = nil // a role that grants nothing
	svc, _ := newService(db, cfg)

	tenantID := insertTenant(ctx, t, db, "role-map")
	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}
	if err := svc.SeedTenant(ctx, tenantID); err != nil {
		t.Fatalf("SeedTenant() = %v", err)
	}

	got, err := svc.TenantRoleMap(ctx, tenantID)
	if err != nil {
		t.Fatalf("TenantRoleMap() = %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("TenantRoleMap() has %d roles, want 3: %v", len(got), got)
	}
	if perms, ok := got["observer"]; !ok || len(perms) != 0 {
		t.Errorf("observer = %v, want an empty permission list, not a missing key", perms)
	}
	if !slices.Equal(got["member"], []string{"notes:read", "notes:write"}) {
		t.Errorf("member = %v, want its two grants", got["member"])
	}
}

// TestRoleByNameNotFound checks a missing role is a not-found error, which
// seeding relies on to tell "absent" from "broken".
func TestRoleByNameNotFound(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	tenantID := insertTenant(ctx, t, db, "missing-role")

	_, err := NewRepository(db).RoleByName(ctx, &tenantID, "ghost")
	if !errors.Is(err, errorz.ErrNotFound) {
		t.Fatalf("RoleByName() = %v, want not found", err)
	}
	if !isNotFound(err) {
		t.Error("isNotFound() did not recognize the error seeding branches on")
	}
}

// TestCopyTemplateRoles checks template roles land in a new tenant with their
// grants, which is how T6.1 onboards a tenant.
func TestCopyTemplateRoles(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	repo := NewRepository(db)
	svc, _ := newService(db, testConfig())
	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}

	// A template role: no tenant.
	tpl, err := repo.CreateRole(ctx, nil, "editor", "Template editor", false)
	if err != nil {
		t.Fatalf("CreateRole(template) = %v", err)
	}
	if !tpl.Template() {
		t.Error("CreateRole with no tenant did not produce a template role")
	}
	if err := repo.SetRolePermissions(ctx, tpl.ID, []string{"notes:write"}); err != nil {
		t.Fatalf("SetRolePermissions() = %v", err)
	}

	tenantID := insertTenant(ctx, t, db, "from-template")
	if err := svc.CopyTemplateRoles(ctx, tenantID); err != nil {
		t.Fatalf("CopyTemplateRoles() = %v", err)
	}

	copied, err := repo.RoleByName(ctx, &tenantID, "editor")
	if err != nil {
		t.Fatalf("RoleByName(editor) = %v", err)
	}
	if copied.Template() {
		t.Error("the copied role is still a template")
	}
	keys, err := repo.RolePermissions(ctx, copied.ID)
	if err != nil {
		t.Fatalf("RolePermissions() = %v", err)
	}
	if !slices.Equal(keys, []string{"notes:write"}) {
		t.Errorf("copied grants = %v, want [notes:write]", keys)
	}
}

// TestSetRolePermissionsReplaces checks a grant list is replaced, not merged.
func TestSetRolePermissionsReplaces(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	repo := NewRepository(db)
	svc, _ := newService(db, testConfig())
	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}
	tenantID := insertTenant(ctx, t, db, "replace")
	role, err := repo.CreateRole(ctx, &tenantID, "staff", "", false)
	if err != nil {
		t.Fatalf("CreateRole() = %v", err)
	}

	steps := [][]string{
		{"notes:read", "notes:write"},
		{"notes:read"},                // narrowed
		{"notes:read:any"},            // swapped
		{},                            // cleared
		{"notes:read", "notes:write"}, // restored
		nil,                           // cleared by a nil slice too
	}
	for _, want := range steps {
		if err := repo.SetRolePermissions(ctx, role.ID, want); err != nil {
			t.Fatalf("SetRolePermissions(%v) = %v", want, err)
		}
		got, err := repo.RolePermissions(ctx, role.ID)
		if err != nil {
			t.Fatalf("RolePermissions() = %v", err)
		}
		if len(got) != len(want) {
			t.Fatalf("grants = %v, want exactly %v", got, want)
		}
		for _, key := range want {
			if !slices.Contains(got, key) {
				t.Errorf("grants = %v, missing %q", got, key)
			}
		}
	}
}

// insertTenant creates a tenant row directly, since these tests only need a
// valid foreign key.
func insertTenant(ctx context.Context, t *testing.T, db *sqlkit.DB, slug string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.Leader().QueryRowContext(ctx,
		`INSERT INTO tenants (slug, name) VALUES ($1, $2) RETURNING id`, slug, slug).Scan(&id)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return id
}

// insertMember creates a user and makes it an active member of the tenant,
// which user_roles requires.
func insertMember(ctx context.Context, t *testing.T, db *sqlkit.DB, tenantID uuid.UUID, label string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := db.Leader().QueryRowContext(ctx,
		`INSERT INTO users (email_enc, email_hash) VALUES ($1, $2) RETURNING id`,
		[]byte("enc:"+label), []byte("hash:"+label)).Scan(&id)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	_, err = db.Leader().ExecContext(ctx,
		`INSERT INTO tenant_members (tenant_id, user_id, status, joined_at)
		 VALUES ($1, $2, 'active', now())`, tenantID, id)
	if err != nil {
		t.Fatalf("insert membership: %v", err)
	}
	return id
}
