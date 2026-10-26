package rbac

import (
	"context"
	"database/sql"
	"errors"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/biairmal/go-identity/internal/platform/apierr"
	"github.com/biairmal/go-identity/internal/platform/database"
	"github.com/biairmal/go-identity/internal/platform/httpx"
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

// RoleInTenant returns one of the tenant's own roles, or errorz.NotFound. A
// template or another tenant's role is not found.
func (r *Repository) RoleInTenant(ctx context.Context, tenantID, id uuid.UUID) (*Role, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT `+roleColumns+` FROM roles WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	return scanRole(row)
}

// UpdateRole writes a role's name and description and bumps its version,
// provided the stored version is still version. A stale version is
// VERSION_CONFLICT.
func (r *Repository) UpdateRole(
	ctx context.Context, tenantID, id uuid.UUID, version int, name, description string,
) (*Role, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`UPDATE roles SET name = $4, description = $5, version = version + 1, updated_at = now()
		 WHERE id = $1 AND tenant_id = $2 AND version = $3
		 RETURNING `+roleColumns, id, tenantID, version, name, description)
	role, err := scanRole(row)
	if isNotFound(err) {
		return nil, httpx.ErrVersionConflict()
	}
	return role, err
}

// DeleteRole deletes one of the tenant's roles. Its grants and assignments go
// with it (ON DELETE CASCADE).
func (r *Repository) DeleteRole(ctx context.Context, tenantID, id uuid.UUID) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`DELETE FROM roles WHERE id = $1 AND tenant_id = $2`, id, tenantID)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: delete role")
	}
	return nil
}

// ListRoles returns one page of the tenant's roles ordered by name, with each
// role's permission and assignment counts, and the total matching roles. A
// non-empty search matches names case-insensitively.
func (r *Repository) ListRoles(
	ctx context.Context, tenantID uuid.UUID, search string, limit, offset int,
) ([]RoleSummary, int64, error) {
	conn := database.Leader(ctx, r.db)
	const where = ` FROM roles r WHERE r.tenant_id = $1 AND ($2 = '' OR r.name ILIKE '%' || $2 || '%')`
	var total int64
	if err := conn.QueryRowContext(ctx, `SELECT count(*)`+where, tenantID, search).Scan(&total); err != nil {
		return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: count roles")
	}
	rows, err := conn.QueryContext(ctx,
		`SELECT r.id, r.tenant_id, r.name, r.description, r.is_system, r.version, r.created_at, r.updated_at,
		   (SELECT count(*) FROM role_permissions rp WHERE rp.role_id = r.id),
		   (SELECT count(*) FROM user_roles ur WHERE ur.role_id = r.id)`+where+`
		 ORDER BY lower(r.name) LIMIT $3 OFFSET $4`, tenantID, search, limit, offset)
	if err != nil {
		return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: list roles")
	}
	defer func() { _ = rows.Close() }()
	var out []RoleSummary
	for rows.Next() {
		var s RoleSummary
		if err := rows.Scan(&s.ID, &s.TenantID, &s.Name, &s.Description, &s.IsSystem, &s.Version,
			&s.CreatedAt, &s.UpdatedAt, &s.PermissionCount, &s.UserCount); err != nil {
			return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: scan role summary")
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: role summary rows")
	}
	return out, total, nil
}

// RoleUserCount is the number of users a role is assigned to.
func (r *Repository) RoleUserCount(ctx context.Context, roleID uuid.UUID) (int, error) {
	var n int
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT count(*) FROM user_roles WHERE role_id = $1`, roleID).Scan(&n)
	if err != nil {
		return 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: role user count")
	}
	return n, nil
}

// HoldsRole reports whether the user is assigned the role in the tenant.
func (r *Repository) HoldsRole(ctx context.Context, tenantID, userID, roleID uuid.UUID) (bool, error) {
	var holds bool
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM user_roles WHERE tenant_id = $1 AND user_id = $2 AND role_id = $3)`,
		tenantID, userID, roleID).Scan(&holds)
	if err != nil {
		return false, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: holds role")
	}
	return holds, nil
}

// RolesByID returns the tenant's roles among ids. An ID of another tenant or
// of a template is left out, so a short result means an unknown ID.
func (r *Repository) RolesByID(ctx context.Context, tenantID uuid.UUID, ids []uuid.UUID) ([]Role, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT `+roleColumns+` FROM roles WHERE tenant_id = $1 AND id = ANY($2) ORDER BY lower(name)`,
		tenantID, ids)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: roles by id")
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

// PermissionsOfRoles is the union of the keys the roles grant.
func (r *Repository) PermissionsOfRoles(ctx context.Context, ids []uuid.UUID) ([]string, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT DISTINCT permission_key FROM role_permissions WHERE role_id = ANY($1) ORDER BY permission_key`, ids)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: permissions of roles")
	}
	return scanStrings(rows, "rbac: permissions of roles")
}

// UserRoles returns the roles each of the users holds in the tenant, ordered
// by name. A user with no role has no entry.
func (r *Repository) UserRoles(
	ctx context.Context, tenantID uuid.UUID, userIDs []uuid.UUID,
) (map[uuid.UUID][]RoleRef, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT ur.user_id, ro.id, ro.name
		 FROM user_roles ur JOIN roles ro ON ro.id = ur.role_id
		 WHERE ur.tenant_id = $1 AND ur.user_id = ANY($2)
		 ORDER BY lower(ro.name)`, tenantID, userIDs)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: user roles")
	}
	defer func() { _ = rows.Close() }()
	out := map[uuid.UUID][]RoleRef{}
	for rows.Next() {
		var userID uuid.UUID
		var ref RoleRef
		if err := rows.Scan(&userID, &ref.ID, &ref.Name); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: scan user role")
		}
		out[userID] = append(out[userID], ref)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: user role rows")
	}
	return out, nil
}

// UnassignRoles removes the user's roles in the tenant, except those in keep.
func (r *Repository) UnassignRoles(ctx context.Context, tenantID, userID uuid.UUID, keep []uuid.UUID) error {
	if keep == nil {
		keep = []uuid.UUID{} // nil is SQL NULL, and NOT (x = ANY(NULL)) would remove nothing
	}
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`DELETE FROM user_roles WHERE tenant_id = $1 AND user_id = $2 AND NOT (role_id = ANY($3))`,
		tenantID, userID, keep)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: unassign roles")
	}
	return nil
}

// Member returns the status of the user's membership in the tenant and
// whether the user is the super admin, or errorz.NotFound without a
// membership. It reads the tenant and user tables directly: a port would make
// rbac and user depend on each other.
func (r *Repository) Member(
	ctx context.Context, tenantID, userID uuid.UUID,
) (status string, superAdmin bool, err error) {
	err = database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT tm.status, u.is_super_admin
		 FROM tenant_members tm JOIN users u ON u.id = tm.user_id
		 WHERE tm.tenant_id = $1 AND tm.user_id = $2`, tenantID, userID).Scan(&status, &superAdmin)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, errorz.NotFound().WithMessage("rbac: user not found")
	}
	if err != nil {
		return "", false, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: member")
	}
	return status, superAdmin, nil
}

// activeHolder joins an assignment to an active user with an active
// membership; only those count as holding a permission.
const activeHolder = `
	JOIN tenant_members tm ON tm.tenant_id = ur.tenant_id AND tm.user_id = ur.user_id AND tm.status = 'active'
	JOIN users u ON u.id = ur.user_id AND u.status = 'active'`

// ActivePermissions is EffectivePermissions for a user who is active and an
// active member of the tenant, and empty otherwise.
func (r *Repository) ActivePermissions(ctx context.Context, tenantID, userID uuid.UUID) ([]string, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT DISTINCT rp.permission_key
		 FROM user_roles ur
		 JOIN role_permissions rp ON rp.role_id = ur.role_id`+activeHolder+`
		 WHERE ur.tenant_id = $1 AND ur.user_id = $2
		 ORDER BY rp.permission_key`, tenantID, userID)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: active permissions")
	}
	return scanStrings(rows, "rbac: active permissions")
}

// RoleManagers counts the active users holding roles:manage in the tenant.
func (r *Repository) RoleManagers(ctx context.Context, tenantID uuid.UUID) (int, error) {
	var n int
	err := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT count(DISTINCT ur.user_id)
		 FROM user_roles ur
		 JOIN role_permissions rp ON rp.role_id = ur.role_id AND rp.permission_key = $2`+activeHolder+`
		 WHERE ur.tenant_id = $1`, tenantID, PermRolesManage).Scan(&n)
	if err != nil {
		return 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("rbac: count role managers")
	}
	return n, nil
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
	if keys == nil {
		keys = []string{} // a nil slice is SQL NULL, and NOT (x = ANY(NULL)) would prune nothing
	}
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

// uniqueViolation is the Postgres error code of a unique index conflict.
const uniqueViolation = "23505"

// scanRole reads one role row, mapping no rows to errorz.NotFound and a name
// already used in the tenant to DUPLICATE.
func scanRole(row *sql.Row) (*Role, error) {
	var r Role
	err := row.Scan(&r.ID, &r.TenantID, &r.Name, &r.Description, &r.IsSystem,
		&r.Version, &r.CreatedAt, &r.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errorz.NotFound().WithMessage("rbac: role not found")
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
			return nil, apierr.New(apierr.ReasonDuplicate)
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
