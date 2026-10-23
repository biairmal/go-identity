# Patterns

Copy-paste examples for the rules in [AGENTS.md](../AGENTS.md).

## Adding a module

1. Create `internal/<module>/` with `module.go`, `config.go`, `model.go`, `dto.go`, `repository.go`,
   `service.go`, `handler.go`.
2. `module.go` exposes `New(cfg Config, deps app-provided values) (*Module, error)` and
   `Register(mux *http.ServeMux)`.
3. Add the module's config block to `app.Config` and one row to `Config.sections()` in
   `internal/app/config.go`.
4. Add one line to `buildModules` in `internal/app/module.go`.

## Talking to another module

Never import it. Declare the port where it is used and wire an adapter in `internal/app`:

```go
// internal/user/ports.go
type TenantLookup interface {
    DefaultTenantID(ctx context.Context) (uuid.UUID, error)
}

// internal/app/adapters.go
type tenantLookup struct{ svc *tenant.Service }

func (a tenantLookup) DefaultTenantID(ctx context.Context) (uuid.UUID, error) { return a.svc.DefaultID(ctx) }
```

## Repositories

Every repository runs SQL on `database.Leader(ctx, db)` for writes (it joins the context transaction when there is
one) and on `db.Follower()` for lists and reports. Services make several writes atomic with `database.WithTx`.

### Named-column updates

Expose intent methods that write only their own columns, never a full-row update, so a field the caller never
loaded is never overwritten:

```go
func (r *Repository) SetStatus(ctx context.Context, tenantID, id uuid.UUID, status string) error {
    res, err := database.Leader(ctx, r.db).ExecContext(ctx,
        `UPDATE users SET status = $3, updated_at = now() WHERE id = $2 AND tenant_id = $1`,
        tenantID, id, status)
    if err != nil {
        return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("user: set status")
    }
    if n, _ := res.RowsAffected(); n == 0 {
        return errorz.NotFound() // never 403: other tenants' IDs cannot be probed
    }
    return nil
}
```

### Optimistic locking on editable aggregates

`users`, `roles` and `tenants` carry `version`. Updates check it and bump it; zero rows on an existing row is a
409 with `meta.reason: VERSION_CONFLICT`:

```go
res, err := conn.ExecContext(ctx,
    `UPDATE roles SET name = $4, version = version + 1, updated_at = now()
     WHERE id = $2 AND tenant_id = $1 AND version = $3`,
    tenantID, id, version, name)
// ...
if n == 0 {
    if exists { return apierr.Conflict(apierr.ReasonVersionConflict) }
    return errorz.NotFound()
}
```

### Soft delete

Opt-in per table. One statement, and unique constraints become partial indexes:

```sql
UPDATE notes SET deleted_at = now() WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL;
CREATE UNIQUE INDEX notes_name_live ON notes (tenant_id, name) WHERE deleted_at IS NULL;
```

### Side effects through the outbox

Emails and queue messages are enqueued in the same transaction as the change, and the worker sends them:

```go
err := database.WithTx(ctx, s.db, func(ctx context.Context) error {
    if err := s.users.Create(ctx, u); err != nil {
        return err
    }
    return s.outbox.Enqueue(ctx, "mail.send", u.ID.String(), msg)
})
```

Senders must tolerate duplicates: a crash between sending and recording the send resends.
