package app

import (
	"context"
)

// bootstrap runs the startup steps that span modules, in order, before the
// service accepts traffic. Each step must be idempotent: it runs on every
// start and on every pod, so it has to find its own earlier work and leave it
// alone. A failure here stops startup rather than serving a half-set-up
// service.
//
// Later milestones add their steps here: the permission catalog sync and role
// seeding (T2.5), and the super admin bootstrap (T3.3).
func (a *App) bootstrap(ctx context.Context, svc *services) error {
	if _, err := svc.tenant.EnsureDefault(ctx); err != nil {
		return err
	}
	return nil
}
