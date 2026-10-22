// Package database holds the Postgres plumbing shared by every module: the pgx
// driver registration, the migration runner, the transaction helper and the
// outbox.
package database

import (
	"database/sql"

	"github.com/jackc/pgx/v5/stdlib"
)

// DriverName is the database/sql driver name sqlkit opens. sqlkit builds a
// key=value DSN for "postgres", which pgx accepts.
const DriverName = "postgres"

// Driver registration is the one init side effect the conventions allow.
func init() {
	sql.Register(DriverName, stdlib.GetDefaultDriver())
}
