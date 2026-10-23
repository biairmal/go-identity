package httpx

import "github.com/go-chi/chi/v5"

// Routes are the route groups a module mounts its handlers into. internal/app
// builds them once, each with its own middleware, so modules never create a
// group themselves.
type Routes struct {
	Root     chi.Router // outside /v1, e.g. /.well-known
	API      chi.Router // /v1, authenticated unless an auth rule makes the path public
	Me       chi.Router // /v1/me: the target is the caller, no extra permission
	Admin    chi.Router // /v1/admin: every route adds r.With(middleware.RequirePermission(az, perm))
	Internal chi.Router // /v1/internal: service tokens only
}
