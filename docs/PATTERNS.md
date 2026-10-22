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
