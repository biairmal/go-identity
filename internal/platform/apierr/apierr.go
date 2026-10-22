// Package apierr builds the API's error responses: an errorz error whose code
// selects the HTTP status and whose meta.reason (TRD 9.2) tells clients what
// happened. Never invent an errorz code: an unknown one maps to 500.
package apierr

import (
	"errors"
	"math"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
)

// Meta keys written on API errors.
const (
	MetaReason     = "reason"
	MetaFields     = "fields"
	MetaRetryAfter = "retry_after"
)

// New returns the error for reason, with the errorz code TRD 9.2 assigns to
// it and meta.reason set. An unknown reason (or ReasonTenantRequired, which
// is not an error) yields a 500, so a typo is loud.
func New(reason Reason) error {
	return build(reason)
}

// WithFields is New plus meta.fields, e.g. PASSWORD_POLICY explaining
// {"password": "too common"}.
func WithFields(reason Reason, fields map[string]string) error {
	return build(reason).WithMeta(MetaFields, fields)
}

// WithRetryAfter is New plus meta.retry_after in whole seconds (rounded up),
// for ACCOUNT_LOCKED and RATE_LIMITED. httpx.Handle copies it into the
// Retry-After header.
func WithRetryAfter(reason Reason, d time.Duration) error {
	return build(reason).WithMeta(MetaRetryAfter, int(math.Ceil(d.Seconds())))
}

// build creates the coded error. Starting from the errorz constructor keeps
// errors.Is(err, errorz.ErrForbidden) and friends working.
func build(reason Reason) *errorz.Error {
	var e *errorz.Error
	switch reasonCodes[reason] {
	case errorz.CodeUnauthorized:
		e = errorz.Unauthorized()
	case errorz.CodeForbidden:
		e = errorz.Forbidden()
	case errorz.CodeBadRequest:
		e = errorz.BadRequest()
	case errorz.CodeNotFound:
		e = errorz.NotFound()
	case errorz.CodeConflict:
		e = errorz.Conflict()
	case errorz.CodeTooManyRequests:
		e = errorz.TooManyRequests()
	default:
		e = errorz.Internal().WithMessage("apierr: unknown reason " + string(reason))
	}
	return e.WithMeta(MetaReason, string(reason))
}

// ReasonOf returns err's meta.reason, or "" when it has none.
func ReasonOf(err error) Reason {
	var e *errorz.Error
	if !errors.As(err, &e) {
		return ""
	}
	r, ok := e.Meta[MetaReason].(string)
	if !ok {
		return ""
	}
	return Reason(r)
}

// RetryAfterOf returns err's meta.retry_after in seconds, if set.
func RetryAfterOf(err error) (int, bool) {
	var e *errorz.Error
	if !errors.As(err, &e) {
		return 0, false
	}
	s, ok := e.Meta[MetaRetryAfter].(int)
	return s, ok
}
