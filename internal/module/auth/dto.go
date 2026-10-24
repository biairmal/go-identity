package auth

// AuthConfigResponse is what the sign-in screen needs to render itself: the
// enabled providers, whether self sign-up is open and the tenancy mode. It is
// built from configuration only and carries nothing secret.
//
//nolint:revive // named for its resource: the package will hold other response DTOs
type AuthConfigResponse struct {
	Providers    ProvidersResponse `json:"providers"`
	Registration bool              `json:"registration"`
	Tenancy      string            `json:"tenancy"`
}

// ProvidersResponse reports which sign-in providers are enabled.
type ProvidersResponse struct {
	Password bool `json:"password"`
	Google   bool `json:"google"`
}

// newAuthConfigResponse reads the public part of the configuration. Client
// IDs and secrets stay behind: the frontend only learns what is switched on.
func newAuthConfigResponse(cfg *Config, tenancy string) AuthConfigResponse {
	return AuthConfigResponse{
		Providers: ProvidersResponse{
			Password: cfg.Providers.Password.Enabled,
			Google:   cfg.Providers.Google.Enabled,
		},
		Registration: cfg.Registration.Enabled,
		Tenancy:      tenancy,
	}
}
