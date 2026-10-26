package tenant

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
)

// Repository reads and writes tenants and memberships. Every write names its
// own columns, so a field the caller never loaded is never overwritten.
type Repository struct {
	db *sqlkit.DB
}

// NewRepository returns a Repository over db.
func NewRepository(db *sqlkit.DB) *Repository { return &Repository{db: db} }

// tenantColumns is the select list for a Tenant.
const tenantColumns = `id, slug, name, status, version, created_at, updated_at`

// EnsureBySlug creates the tenant with slug if it does not exist and returns
// it either way. It is safe to run on every start and from several pods at
// once: the insert does nothing on a conflict, and the row is then read back.
func (r *Repository) EnsureBySlug(ctx context.Context, slug, name string) (*Tenant, bool, error) {
	conn := database.Leader(ctx, r.db)
	res, err := conn.ExecContext(ctx,
		`INSERT INTO tenants (slug, name) VALUES ($1, $2) ON CONFLICT (slug) DO NOTHING`, slug, name)
	if err != nil {
		return nil, false, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: ensure")
	}
	created := false
	if n, err := res.RowsAffected(); err == nil && n > 0 {
		created = true
	}
	t, err := r.BySlug(ctx, slug)
	if err != nil {
		return nil, false, err
	}
	return t, created, nil
}

// uniqueViolation is the Postgres error code of a unique index conflict.
const uniqueViolation = "23505"

// Create inserts a tenant and returns it. A slug already in use is DUPLICATE.
func (r *Repository) Create(ctx context.Context, slug, name string) (*Tenant, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`INSERT INTO tenants (slug, name) VALUES ($1, $2) RETURNING `+tenantColumns, slug, name)
	t, err := scanTenant(row)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == uniqueViolation {
		return nil, apierr.New(apierr.ReasonDuplicate)
	}
	return t, err
}

// TenantSummary is one tenant with its member count, for the admin list.
type TenantSummary struct { //nolint:revive // named for its resource: the tenant package holds several summary types
	Tenant
	MemberCount int
}

// ListPage returns one page of tenants, newest first, with each tenant's
// member count (members that have not been removed), and the total matching.
// A non-empty status filters by status; a non-empty search matches the slug
// or name case-insensitively.
func (r *Repository) ListPage(
	ctx context.Context, status, search string, limit, offset int,
) ([]TenantSummary, int64, error) {
	conn := database.Leader(ctx, r.db)
	const where = ` FROM tenants t
		WHERE ($1 = '' OR t.status = $1)
		  AND ($2 = '' OR t.slug ILIKE '%' || $2 || '%' OR t.name ILIKE '%' || $2 || '%')`
	var total int64
	if err := conn.QueryRowContext(ctx, `SELECT count(*)`+where, status, search).Scan(&total); err != nil {
		return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: count")
	}
	rows, err := conn.QueryContext(ctx,
		`SELECT t.id, t.slug, t.name, t.status, t.version, t.created_at, t.updated_at,
		   (SELECT count(*) FROM tenant_members m WHERE m.tenant_id = t.id AND m.status <> 'removed')`+where+`
		 ORDER BY t.created_at DESC, t.id LIMIT $3 OFFSET $4`, status, search, limit, offset)
	if err != nil {
		return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: list page")
	}
	defer func() { _ = rows.Close() }()
	var out []TenantSummary
	for rows.Next() {
		var s TenantSummary
		if err := rows.Scan(&s.ID, &s.Slug, &s.Name, &s.Status, &s.Version,
			&s.CreatedAt, &s.UpdatedAt, &s.MemberCount); err != nil {
			return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: scan summary")
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: summary rows")
	}
	return out, total, nil
}

// Update writes a tenant's name and status and bumps its version, provided
// the stored version is still version. A stale version is VERSION_CONFLICT,
// and a missing row is not found.
func (r *Repository) Update(ctx context.Context, id uuid.UUID, version int, name, status string) (*Tenant, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`UPDATE tenants SET name = $3, status = $4, version = version + 1, updated_at = now()
		 WHERE id = $1 AND version = $2
		 RETURNING `+tenantColumns, id, version, name, status)
	t, err := scanTenant(row)
	if errors.Is(err, errorz.ErrNotFound) {
		if _, byID := r.ByID(ctx, id); byID != nil {
			return nil, byID // not found
		}
		return nil, apierr.New(apierr.ReasonVersionConflict)
	}
	return t, err
}

// BySlug returns the tenant with slug, or errorz.NotFound.
func (r *Repository) BySlug(ctx context.Context, slug string) (*Tenant, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT `+tenantColumns+` FROM tenants WHERE slug = $1`, slug)
	return scanTenant(row)
}

// ByID returns the tenant with id, or errorz.NotFound.
func (r *Repository) ByID(ctx context.Context, id uuid.UUID) (*Tenant, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT `+tenantColumns+` FROM tenants WHERE id = $1`, id)
	return scanTenant(row)
}

// List returns every tenant, oldest first. It is used at startup to seed
// roles into each tenant, so it reads the leader.
func (r *Repository) List(ctx context.Context) ([]Tenant, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT `+tenantColumns+` FROM tenants ORDER BY created_at, id`)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: list")
	}
	defer func() { _ = rows.Close() }()
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.Version, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: scan")
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: list rows")
	}
	return out, nil
}

// SetStatus moves a tenant between active and suspended, checking the version
// so a concurrent edit is reported rather than silently lost.
func (r *Repository) SetStatus(ctx context.Context, id uuid.UUID, version int, status string) error {
	res, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`UPDATE tenants SET status = $3, version = version + 1, updated_at = now()
		 WHERE id = $1 AND version = $2`, id, version, status)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: set status")
	}
	return r.checkUpdate(ctx, id, res)
}

// checkUpdate turns zero affected rows into the right error: a conflict when
// the row exists (a stale version) and not found when it does not.
func (r *Repository) checkUpdate(ctx context.Context, id uuid.UUID, res sql.Result) error {
	n, err := res.RowsAffected()
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: rows affected")
	}
	if n > 0 {
		return nil
	}
	if _, err := r.ByID(ctx, id); err != nil {
		return err // not found
	}
	return errorz.Conflict().WithMessage("tenant: version conflict")
}

// AddMember adds a membership, or leaves it unchanged when it already
// exists, so inviting the same member twice is not an error. An active
// membership is stamped with its join time.
func (r *Repository) AddMember(ctx context.Context, tenantID, userID uuid.UUID, status string) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`INSERT INTO tenant_members (tenant_id, user_id, status, joined_at)
		 VALUES ($1, $2, $3, CASE WHEN $3 = 'active' THEN now() END)
		 ON CONFLICT (tenant_id, user_id) DO NOTHING`,
		tenantID, userID, status)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: add member")
	}
	return nil
}

// SetMemberStatus changes one membership's status. Activating a membership
// stamps joined_at the first time.
func (r *Repository) SetMemberStatus(ctx context.Context, tenantID, userID uuid.UUID, status string) error {
	res, err := database.Leader(ctx, r.db).ExecContext(ctx,
		`UPDATE tenant_members
		 SET status = $3,
		     joined_at = CASE WHEN $3 = 'active' AND joined_at IS NULL THEN now() ELSE joined_at END
		 WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID, status)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: set member status")
	}
	n, err := res.RowsAffected()
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: rows affected")
	}
	if n == 0 {
		return errorz.NotFound().WithMessage("tenant: membership not found")
	}
	return nil
}

// Member returns one membership, or errorz.NotFound.
func (r *Repository) Member(ctx context.Context, tenantID, userID uuid.UUID) (*Member, error) {
	row := database.Leader(ctx, r.db).QueryRowContext(ctx,
		`SELECT tenant_id, user_id, status, joined_at
		 FROM tenant_members WHERE tenant_id = $1 AND user_id = $2`, tenantID, userID)
	var m Member
	if err := row.Scan(&m.TenantID, &m.UserID, &m.Status, &m.JoinedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errorz.NotFound().WithMessage("tenant: membership not found")
		}
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: scan membership")
	}
	return &m, nil
}

// MembershipsOf lists the tenants a user belongs to, with the membership
// status, so sign-in can offer the tenants to choose from.
func (r *Repository) MembershipsOf(ctx context.Context, userID uuid.UUID) ([]Membership, error) {
	rows, err := database.Leader(ctx, r.db).QueryContext(ctx,
		`SELECT t.id, t.slug, t.name, t.status, m.status
		 FROM tenant_members m
		 JOIN tenants t ON t.id = m.tenant_id
		 WHERE m.user_id = $1
		 ORDER BY t.created_at, t.id`, userID)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: memberships")
	}
	defer func() { _ = rows.Close() }()
	var out []Membership
	for rows.Next() {
		var m Membership
		if err := rows.Scan(&m.TenantID, &m.Slug, &m.Name, &m.TenantStatus, &m.MemberStatus); err != nil {
			return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: scan membership")
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: memberships rows")
	}
	return out, nil
}

// Membership is a tenant seen from one user's side.
type Membership struct {
	TenantID     uuid.UUID
	Slug         string
	Name         string
	TenantStatus string
	MemberStatus string
}

// scanTenant reads one tenant row, mapping no rows to errorz.NotFound.
func scanTenant(row *sql.Row) (*Tenant, error) {
	var t Tenant
	if err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.Status, &t.Version, &t.CreatedAt, &t.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errorz.NotFound().WithMessage("tenant: not found")
		}
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("tenant: scan")
	}
	return &t, nil
}
