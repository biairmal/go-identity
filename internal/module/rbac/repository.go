package rbac

import (
	"context"
	"database/sql"
	"errors"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// Repository reads and writes the catalog, roles and assignments.
type Repository struct {
	db *sqlkit.DB
}

// NewRepository returns a Repository over db.
func NewRepository(db *sqlkit.DB) *Repository { return &Repository{db: db} }

// roleColumns is the select list for a Role.
const roleColumns = `id, tenant_id, name, description, is_system, version, created_at, updated_at`

// UpsertPermission inserts a catalog key or updates its description. It never
// deletes, so a key a role still grants cannot disappear from under it.
func (r *Repository) UpsertPermission(ctx context.Context, e CatalogEntry) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`INSERT INTO permissions (key, description, is_system) VALUES ($1, $2, $3)
		 ON CONFLICT (key) DO UPDATE SET description = EXCLUDED.description, is_system = EXCLUDED.is_system`,
		e.Key, e.Description, e.IsSystem)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: upsert permission")
	}
	return nil
}

// Permissions lists the catalog, ordered by key.
func (r *Repository) Permissions(ctx context.Context) ([]CatalogEntry, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT key, description, is_system FROM permissions ORDER BY key`)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: list permissions")
	}
	defer func() { _ = rows.Close() }()
	var out []CatalogEntry
	for rows.Next() {
		var e CatalogEntry
		if err := rows.Scan(&e.Key, &e.Description, &e.IsSystem); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: scan permission")
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: permission rows")
	}
	return out, nil
}

// OrphanedPermissions returns the keys a role still grants that are no longer
// in the configured catalog, so startup can warn instead of deleting them.
func (r *Repository) OrphanedPermissions(ctx context.Context, configured []string) ([]string, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT DISTINCT rp.permission_key
		 FROM role_permissions rp
		 WHERE NOT (rp.permission_key = ANY($1))
		 ORDER BY rp.permission_key`, configured)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: orphaned permissions")
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: scan orphan")
		}
		out = append(out, key)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: orphan rows")
	}
	return out, nil
}

// CreateRole inserts a role and returns it. A nil tenantID creates a
// template.
func (r *Repository) CreateRole(
	ctx context.Context, tenantID *uuid.UUID, name, description string, isSystem bool,
) (*Role, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`INSERT INTO roles (tenant_id, name, description, is_system) VALUES ($1, $2, $3, $4)
		 RETURNING `+roleColumns, tenantID, name, description, isSystem)
	return scanRole(row)
}

// RoleByName finds a role by its case-insensitive name inside one tenant, or
// among the templates when tenantID is nil.
func (r *Repository) RoleByName(ctx context.Context, tenantID *uuid.UUID, name string) (*Role, error) {
	conn := database.Leader(ctx, r.db)
	var row *sql.Row
	if tenantID == nil {
		row = conn.QueryRowContext(ctx,
			`SELECT `+roleColumns+` FROM roles WHERE tenant_id IS NULL AND lower(name) = lower($1)`, name)
	} else {
		row = conn.QueryRowContext(ctx,
			`SELECT `+roleColumns+` FROM roles WHERE tenant_id = $1 AND lower(name) = lower($2)`, *tenantID, name)
	}
	return scanRole(row)
}

// RolesIn lists a tenant's roles, or the templates when tenantID is nil.
func (r *Repository) RolesIn(ctx context.Context, tenantID *uuid.UUID) ([]Role, error) {
	conn := database.Leader(ctx, r.db)
	var (
		rows *sql.Rows
		err  error
	)
	if tenantID == nil {
		rows, err = conn.QueryContext(ctx,
			`SELECT `+roleColumns+` FROM roles WHERE tenant_id IS NULL ORDER BY name`)
	} else {
		rows, err = conn.QueryContext(ctx,
			`SELECT `+roleColumns+` FROM roles WHERE tenant_id = $1 ORDER BY name`, *tenantID)
	}
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: list roles")
	}
	defer func() { _ = rows.Close() }()
	var out []Role
	for rows.Next() {
		role, err := scanRoleRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *role)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: role rows")
	}
	return out, nil
}

// SetRolePermissions replaces a role's grants with keys, in one statement
// pair so the role is never briefly without its permissions.
func (r *Repository) SetRolePermissions(ctx context.Context, roleID uuid.UUID, keys []string) error {
	conn := database.Leader(ctx, r.db)
	if _, err := conn.ExecContext(ctx,
		`DELETE FROM role_permissions WHERE role_id = $1 AND NOT (permission_key = ANY($2))`,
		roleID, keys); err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: prune role permissions")
	}
	if len(keys) == 0 {
		return nil
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO role_permissions (role_id, permission_key)
		 SELECT $1, key FROM unnest($2::text[]) AS key
		 ON CONFLICT DO NOTHING`, roleID, keys); err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: grant role permissions")
	}
	return nil
}

// RolePermissions lists the keys one role grants.
func (r *Repository) RolePermissions(ctx context.Context, roleID uuid.UUID) ([]string, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT permission_key FROM role_permissions WHERE role_id = $1 ORDER BY permission_key`, roleID)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: role permissions")
	}
	return scanStrings(rows, "rbac: role permissions")
}

// AssignRole grants one role to a user in a tenant. The composite foreign key
// refuses a role from another tenant, and a repeat grant is not an error.
func (r *Repository) AssignRole(ctx context.Context, tenantID, userID, roleID uuid.UUID, grantedBy *uuid.UUID) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`INSERT INTO user_roles (tenant_id, user_id, role_id, granted_by) VALUES ($1, $2, $3, $4)
		 ON CONFLICT (tenant_id, user_id, role_id) DO NOTHING`, tenantID, userID, roleID, grantedBy)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: assign role")
	}
	return nil
}

// EffectivePermissions is the union of the permissions of every role a user
// holds in a tenant, in one query.
func (r *Repository) EffectivePermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT DISTINCT rp.permission_key
		 FROM user_roles ur
		 JOIN role_permissions rp ON rp.role_id = ur.role_id
		 WHERE ur.tenant_id = $1 AND ur.user_id = $2
		 ORDER BY rp.permission_key`, tenantID, userID)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: effective permissions")
	}
	return scanStrings(rows, "rbac: effective permissions")
}

// RoleNames lists the names of the roles a user holds in a tenant, which go
// into the token's roles claim.
func (r *Repository) RoleNames(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT ro.name
		 FROM user_roles ur
		 JOIN roles ro ON ro.id = ur.role_id
		 WHERE ur.tenant_id = $1 AND ur.user_id = $2
		 ORDER BY ro.name`, tenantID, userID)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: role names")
	}
	return scanStrings(rows, "rbac: role names")
}

// TenantRoleMap is the role name to permissions map of one tenant, served to
// go-sdk authz with source identity.
func (r *Repository) TenantRoleMap(ctx context.Context, tenantID uuid.UUID) (map[string][]string, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT ro.name, COALESCE(rp.permission_key, '')
		 FROM roles ro
		 LEFT JOIN role_permissions rp ON rp.role_id = ro.id
		 WHERE ro.tenant_id = $1
		 ORDER BY ro.name, rp.permission_key`, tenantID)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: tenant role map")
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]string{}
	for rows.Next() {
		var name, key string
		if err := rows.Scan(&name, &key); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: scan role map")
		}
		if _, ok := out[name]; !ok {
			out[name] = []string{}
		}
		if key != "" {
			out[name] = append(out[name], key)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: role map rows")
	}
	return out, nil
}

// scanStrings reads a single text column into a slice.
func scanStrings(rows *sql.Rows, what string) ([]string, error) {
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage(what)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage(what)
	}
	return out, nil
}

// scanRole reads one role row, mapping no rows to errorz.NotFound.
func scanRole(row *sql.Row) (*Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.Description, &r.IsSystem,
		&r.Version, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errorz.NotFound().WithMessage("rbac: role not found")
		}
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: scan role")
	}
	return &r, nil
}

// scanRoleRow reads one role from a multi-row result.
func scanRoleRow(rows *sql.Rows) (*Role, error) {
	var r Role
	err := rows.Scan(&r.ID, &r.TenantID, &r.Name, &r.Description, &r.IsSystem,
		&r.Version, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: scan role")
	}
	return &r, nil
}
