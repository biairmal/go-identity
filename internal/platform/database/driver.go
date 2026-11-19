// Package database holds the Postgres plumbing shared by every module: the pgx
// driver registration, the migration runner, the transaction helper and the
// outbox.
package database

import (
	"database/sql"

	"github.com/biairmal/go-sdk/lib/tracer/tracesql"
	"github.com/jackc/pgx/v5/stdlib"
)

// DriverName is the database/sql driver name sqlkit opens. sqlkit builds a
// key=value DSN for "postgres", which pgx accepts.
const DriverName = "postgres"

// Driver registration is the one init side effect the conventions allow. The
// driver is traced: a statement run under a span becomes its child span, with
// the SQL text and never the arguments. With tracing off the global OTel
// provider is a no-op, so the wrapper costs almost nothing.
func init() {
	sql.Register(DriverName, tracesql.WrapDriver(stdlib.GetDefaultDriver()))
}
