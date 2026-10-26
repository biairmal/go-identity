package auth

import (
	"context"
	"time"

	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/validator"

	"github.com/biairmal/go-identity/internal/module/auth/password"
	"github.com/biairmal/go-identity/internal/module/auth/token"
	"github.com/biairmal/go-identity/internal/platform/apierr"
)

// serviceTokenTTL is how long a service token lives (TRD 9.4).
const serviceTokenTTL = 5 * time.Minute

// grantTypeClientCredentials is the only grant_type POST /v1/auth/token
// accepts.
const grantTypeClientCredentials = "client_credentials"

// ServiceTokens runs POST /v1/auth/token (TRD 9.4): a resource service trades
// its configured client credentials for a short-lived token scoped to
// /v1/internal.
type ServiceTokens struct {
	cfg    *Config
	v      validator.Validator
	tokens *token.Builder
}

// Issue checks grant_type and the client's credentials against
// modules.auth.service_clients and signs a scope:internal token. An unknown
// client_id or a wrong secret both answer INVALID_CLIENT, so neither reveals
// which client IDs are configured.
func (s *ServiceTokens) Issue(ctx context.Context, in *ServiceTokenRequest) (*ServiceTokenResponse, error) {
	if err := s.v.ValidateStruct(in); err != nil {
		return nil, err
	}
	if in.GrantType != grantTypeClientCredentials {
		return nil, apierr.New(apierr.ReasonUnsupportedGrantType)
	}
	sc, ok := s.cfg.ServiceClient(in.ClientID)
	if !ok {
		return nil, apierr.New(apierr.ReasonInvalidClient)
	}
	match, _, err := password.Verify(in.ClientSecret, sc.SecretHash)
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: verify service client secret")
	}
	if !match {
		return nil, apierr.New(apierr.ReasonInvalidClient)
	}
	signed, err := s.tokens.Service(ctx, sc.ID, serviceTokenTTL)
	if err != nil {
		return nil, err
	}
	return &ServiceTokenResponse{
		AccessToken: signed,
		TokenType:   tokenTypeBearer,
		ExpiresIn:   int(serviceTokenTTL.Seconds()),
	}, nil
}
