// Package tracing holds the span helpers shared by every module.
package tracing

import (
	"net/http"

	"github.com/biairmal/go-sdk/lib/httpkit/handler"
	"github.com/biairmal/go-sdk/lib/tracer"
)

// End ends span, first recording err when it is a server-side failure: one the
// API answers with a 5xx (an errorz internal, bad gateway or unavailable code,
// or an error with no errorz code). A 4xx is the API working as designed, so it
// leaves the span without an error. Call it deferred with a named error result:
//
//	ctx, span := s.tr.Start(ctx, "note.Update")
//	defer func() { tracing.End(span, err) }()
func End(span tracer.Span, err error) {
	if err != nil && handler.StatusCodeFromError(err) >= http.StatusInternalServerError {
		span.SetError(err)
	}
	span.End()
}
