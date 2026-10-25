package rbac

import (
	"context"
	"testing"
	"time"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/validator"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/testkit"
)

// TestSetPermissionsWaitsForTheTenantLock has a change hold the tenant's
// admin lock while it strips one of the last two roles:manage holders. A
// concurrent change stripping the other must wait for it, then count again
// and refuse with LAST_ADMIN. Without the lock both would see two holders and
// both succeed, leaving none.
func TestSetPermissionsWaitsForTheTenantLock(t *testing.T) {
	db := testkit.Postgres(t)
	ctx := context.Background()
	svc, _ := newService(db, testConfig())
	svc.v = validator.New(validator.DefaultConfig())
	if err := svc.SyncCatalog(ctx); err != nil {
		t.Fatalf("SyncCatalog() = %v", err)
	}
	tenantID := insertTenant(ctx, t, db, "acme")
	a, b := insertMember(ctx, t, db, tenantID, "a"), insertMember(ctx, t, db, tenantID, "b")
	if _, err := db.Leader().ExecContext(ctx, `UPDATE users SET status = 'active'`); err != nil {
		t.Fatalf("activate users: %v", err)
	}
	roleFor := func(user uuid.UUID, name string) *Role {
		role, err := svc.repo.CreateRole(ctx, &tenantID, name, "", false)
		if err != nil {
			t.Fatalf("CreateRole: %v", err)
		}
		if err := svc.repo.SetRolePermissions(ctx, role.ID, []string{PermRolesManage}); err != nil {
			t.Fatalf("SetRolePermissions: %v", err)
		}
		if err := svc.repo.AssignRole(ctx, tenantID, user, role.ID, nil); err != nil {
			t.Fatalf("AssignRole: %v", err)
		}
		return role
	}
	one, two := roleFor(a, "one"), roleFor(b, "two")
	asA := sdkauth.ContextWithClaims(ctx, sdkauth.NewClaims(map[string]any{"sub": a.String(), "tid": tenantID.String()}))

	done := make(chan error, 1)
	err := database.WithTx(ctx, db, func(tx context.Context) error {
		if err := database.LockXact(tx, adminLock(tenantID)); err != nil {
			return err
		}
		go func() {
			_, err := svc.SetPermissions(asA, two.ID, two.Version, &SetPermissionsRequest{Permissions: []string{}})
			done <- err
		}()
		select {
		case err := <-done:
			t.Fatalf("SetPermissions returned %v while another change held the tenant lock", err)
		case <-time.After(300 * time.Millisecond):
		}
		return svc.repo.SetRolePermissions(tx, one.ID, nil)
	})
	if err != nil {
		t.Fatalf("holding transaction: %v", err)
	}
	if err := <-done; apierr.ReasonOf(err) != apierr.ReasonLastAdmin {
		t.Fatalf("SetPermissions after the other change = %v, want LAST_ADMIN", err)
	}
	if n, err := svc.repo.RoleManagers(ctx, tenantID); err != nil || n != 1 {
		t.Errorf("RoleManagers = %d, %v; want 1", n, err)
	}
}
