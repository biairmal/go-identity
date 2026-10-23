package app

import (
	"context"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// bootstrap runs the startup steps that span modules, in order, before the
// service accepts traffic. Each step must be idempotent: it runs on every
// start and on every pod, so it has to find its own earlier work and leave it
// alone. A failure here stops startup rather than serving a half-set-up
// service.
//
// Later milestones add their steps here: the super admin bootstrap (T3.3).
func (a *App) bootstrap(ctx context.Context, svc *services) error {
	// One transaction, so a start that fails half way leaves nothing
	// behind: either the tenant, its roles and the audit rows are all
	// there, or none of them are.
	return database.WithTx(ctx, a.db, func(ctx context.Context) error {
		if err := svc.rbac.SyncCatalog(ctx); err != nil {
			return err
		}
		if _, err := svc.tenant.EnsureDefault(ctx); err != nil {
			return err
		}
		return a.seedRoles(ctx, svc)
	})
}

// seedRoles creates the configured roles in every tenant that lacks them.
// internal/app lists the tenants and hands each one to rbac, so rbac never
// has to know about the tenant module.
func (a *App) seedRoles(ctx context.Context, svc *services) error {
	tenants, err := svc.tenant.List(ctx)
	if err != nil {
		return err
	}
	for i := range tenants {
		if err := svc.rbac.SeedTenant(ctx, tenants[i].ID); err != nil {
			return err
		}
	}
	return nil
}
