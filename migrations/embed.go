// Package migrations embeds the goose SQL migrations, so the binary is
// self-contained.
package migrations

import "embed"

// FS holds every *.sql migration in this directory.
//
//go:embed *.sql
var FS embed.FS
