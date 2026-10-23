// Package requestip carries the caller's IP address through the context, so
// code far from the HTTP layer (the audit log) can record it without taking a
// *http.Request.
package requestip

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// ctxKey is unexported, so only this package can set the value.
type ctxKey struct{}

// trustedHeaders are consulted in order when the service runs behind a proxy.
// They are forgeable by a direct client, so the value is only ever used for
// audit and rate-limit keys, never for an authorisation decision.
var trustedHeaders = []string{"X-Forwarded-For", "X-Real-Ip"}

// Middleware records the caller's IP in the request context.
func Middleware(trustProxy bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r.WithContext(With(r.Context(), From(r, trustProxy))))
		})
	}
}

// With puts ip in the context. An empty or unparseable address is stored as
// an empty string, which the audit log writes as NULL.
func With(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ctxKey{}, ip)
}

// Get returns the caller's IP, or an empty string when there is none.
func Get(ctx context.Context) string {
	ip, ok := ctx.Value(ctxKey{}).(string)
	if !ok {
		return ""
	}
	return ip
}

// From extracts the caller's IP from r. With trustProxy it takes the first
// address of the first trusted header, which is the original client when a
// proxy appends to the chain; otherwise it uses the connection's address.
func From(r *http.Request, trustProxy bool) string {
	if trustProxy {
		for _, h := range trustedHeaders {
			if ip := firstIP(r.Header.Get(h)); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return validIP(r.RemoteAddr)
	}
	return validIP(host)
}

// firstIP returns the first valid address of a comma-separated list.
func firstIP(header string) string {
	for part := range strings.SplitSeq(header, ",") {
		if ip := validIP(strings.TrimSpace(part)); ip != "" {
			return ip
		}
	}
	return ""
}

// validIP returns raw when it parses as an IP address, else an empty string,
// so a forged header cannot put arbitrary text in the audit log.
func validIP(raw string) string {
	if net.ParseIP(raw) == nil {
		return ""
	}
	return raw
}
