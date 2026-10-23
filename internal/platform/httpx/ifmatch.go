package httpx

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/biairmal/go-sdk/lib/errorz"

	"github.com/biairmal/go-identity/internal/platform/apierr"
)

// IfMatchHeader carries the version an update is based on: If-Match: "3".
const IfMatchHeader = "If-Match"

// Version returns the version a PATCH or PUT is based on: the If-Match header
// when present, else bodyVersion (the body's "version" field; nil when the
// body has none). A route that requires one and gets neither answers 428; a
// malformed header is a 400.
func Version(r *http.Request, bodyVersion *int) (int, error) {
	raw := strings.TrimSpace(r.Header.Get(IfMatchHeader))
	if raw == "" {
		if bodyVersion == nil {
			return 0, errorz.PreconditionRequired().
				WithMessage(`If-Match: "<version>" or a version field is required`)
		}
		return checkVersion(*bodyVersion)
	}
	raw = strings.TrimPrefix(raw, "W/")
	if unq, err := strconv.Unquote(raw); err == nil {
		raw = unq
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, badField(IfMatchHeader, `must be a quoted version number, e.g. "3"`)
	}
	return checkVersion(n)
}

func checkVersion(n int) (int, error) {
	if n < 1 {
		return 0, badField("version", "must be a positive integer")
	}
	return n, nil
}

// ErrVersionConflict is the 409 a repository returns when the row's version
// no longer matches.
func ErrVersionConflict() error { return apierr.New(apierr.ReasonVersionConflict) }
