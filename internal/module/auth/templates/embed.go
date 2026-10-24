package templates

import "embed"

// FS holds every mail body in this directory, so the binary is
// self-contained.
//
//go:embed *.txt
var FS embed.FS
