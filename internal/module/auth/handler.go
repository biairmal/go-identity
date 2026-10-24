package auth

import "net/http"

// authConfigPath is the public endpoint the sign-in screen reads, below /v1.
const authConfigPath = "/auth/config"

// getAuthConfig answers GET /v1/auth/config. Configuration is fixed for the
// life of the process, so the response is built once in New.
func (m *Module) getAuthConfig(*http.Request) (any, error) {
	return m.authConfig, nil
}
