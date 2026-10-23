package audit

import (
	"context"

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
