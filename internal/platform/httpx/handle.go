package httpx

import (
	"net/http"
	"strconv"

	"github.com/biairmal/go-sdk/lib/httpkit/handler"

	"github.com/biairmal/go-identity/internal/platform/apierr"
)

// Handle is handler.Handle plus the Retry-After header for errors carrying
// meta.retry_after (RATE_LIMITED, ACCOUNT_LOCKED). Use it for every route.
func Handle(h handler.Func) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		handler.Handle(func(r *http.Request) (any, error) {
			data, err := h(r)
			if s, ok := apierr.RetryAfterOf(err); ok {
				w.Header().Set("Retry-After", strconv.Itoa(s))
			}
			return data, err
		})(w, r)
	}
}
