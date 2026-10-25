package audit

import (
	"context"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"
	"github.com/google/uuid"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// Row is one audit_log row as stored. The nullable columns are pointers, so a
// platform-level event writes NULL rather than a zero UUID.
type Row struct {
	TenantID   *uuid.UUID
	ActorID    *uuid.UUID
	Action     string
	TargetType string
	TargetID   string
	Before     []byte
	After      []byte
	IP         *string
	RequestID  string
}

// Repository appends to audit_log. There is no update or delete: the app role
// holds no such privilege on the table.
type Repository struct {
	db *sqlkit.DB
}

// NewRepository returns a Repository over db.
func NewRepository(db *sqlkit.DB) *Repository { return &Repository{db: db} }

// Insert appends one row through the context's connection, so it joins the
// caller's transaction when there is one.
func (r *Repository) Insert(ctx context.Context, row *Row) error {
	_, err := database.Leader(ctx, r.db).ExecContext(ctx, `
		INSERT INTO audit_log
			(tenant_id, actor_id, action, target_type, target_id, before, after, ip, request_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		row.TenantID, row.ActorID, row.Action, row.TargetType, row.TargetID,
		row.Before, row.After, row.IP, row.RequestID)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("audit: insert")
	}
	return nil
}

// Entry is one audit_log row as read back, with the actor's display name.
type Entry struct {
	ID         int64
	At         time.Time
	ActorID    *uuid.UUID
	ActorName  *string
	Action     string
	TargetType string
	TargetID   string
	Before     []byte
	After      []byte
	IP         *string
	RequestID  string
}

// Filter narrows a tenant's audit log. Zero values do not filter.
type Filter struct {
	ActorID *uuid.UUID
	// Action is a LIKE pattern; without a wildcard it matches the action.
	Action string
	From   *time.Time
	To     *time.Time
	Limit  int
	Offset int
}

// entryFrom selects one tenant's entries. It joins users, owned by the user
// module, for the actor's display name: a read a port could only serve one
// row at a time.
const entryFrom = `
	FROM audit_log a
	LEFT JOIN users u ON u.id = a.actor_id
	WHERE a.tenant_id = $1
	  AND ($2::uuid IS NULL OR a.actor_id = $2)
	  AND ($3 = '' OR a.action LIKE $3)
	  AND ($4::timestamptz IS NULL OR a.at >= $4)
	  AND ($5::timestamptz IS NULL OR a.at <= $5)`

// List returns one page of a tenant's entries, newest first, and the total
// matching.
func (r *Repository) List(ctx context.Context, tenantID uuid.UUID, f *Filter) ([]Entry, int64, error) {
	conn := database.Leader(ctx, r.db)
	args := []any{tenantID, f.ActorID, f.Action, f.From, f.To}
	var total int64
	if err := conn.QueryRowContext(ctx, `SELECT count(*)`+entryFrom, args...).Scan(&total); err != nil {
		return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("audit: count")
	}
	rows, err := conn.QueryContext(ctx,
		`SELECT a.id, a.at, a.actor_id, u.display_name, a.action, a.target_type, a.target_id,
		        a.before, a.after, host(a.ip), a.request_id`+entryFrom+`
		 ORDER BY a.at DESC, a.id DESC LIMIT $6 OFFSET $7`, append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("audit: list")
	}
	defer func() { _ = rows.Close() }()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.At, &e.ActorID, &e.ActorName, &e.Action, &e.TargetType, &e.TargetID,
			&e.Before, &e.After, &e.IP, &e.RequestID); err != nil {
			return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("audit: scan")
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("audit: rows")
	}
	return out, total, nil
}
