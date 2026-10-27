// Package sampleresource is the smallest resource service that trusts
// identity, used by the end-to-end suite: go-sdk auth validates identity's
// access tokens through its JWKS, go-sdk authz maps the caller's roles to
// permissions through identity's internal role endpoint (source identity,
// fetched with a client-credentials service token), and every note is scoped
// to the token's tenant and owner. It is not shipped.
package sampleresource

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"sync"

	"github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/authz"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/httpkit/handler"
	"github.com/biairmal/go-sdk/lib/httpkit/middleware"
	"github.com/biairmal/go-sdk/lib/httpkit/response"
	"github.com/go-chi/chi/v5"
)

// Permissions the service checks. identity's catalog must list them.
const (
	PermRead    = "notes:read"
	PermReadAny = "notes:read:any"
	PermWrite   = "notes:write"
)

// Config points the service at identity.
type Config struct {
	// IdentityURL is identity's base URL: JWKS, /v1/auth/token and
	// /v1/internal all hang off it.
	IdentityURL string
	// ClientID and ClientSecret are this service's entry in identity's
	// modules.auth.service_clients.
	ClientID     string
	ClientSecret string
}

// Note is one stored note. TenantID and OwnerID come from the token, never
// from the request.
type Note struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	OwnerID  string `json:"owner_id"`
	Text     string `json:"text"`
}

type service struct {
	cfg Config
	az  authz.Authorizer

	// ponytail: in-memory table; the queries below are what a Postgres
	// repository would run (tenant_id in every WHERE).
	mu    sync.Mutex
	notes []Note
}

// New builds the service's HTTP handler. Every route needs a valid token from
// identity; POST /notes needs notes:write, the reads need notes:read (own
// notes) or notes:read:any (every note in the caller's tenant).
func New(cfg Config) (http.Handler, error) {
	v, err := auth.NewRS256(auth.WithJWKSURL(cfg.IdentityURL+"/.well-known/jwks.json"),
		auth.WithExpectedIssuer("identity"), auth.WithExpectedAudience("api"))
	if err != nil {
		return nil, err
	}
	s := &service{cfg: cfg}
	s.az, err = authz.New(&authz.Config{Source: authz.SourceIdentity, IdentityURL: cfg.IdentityURL},
		authz.WithServiceToken(s.serviceToken))
	if err != nil {
		return nil, err
	}

	r := chi.NewRouter()
	r.Use(middleware.Auth(v))
	r.With(middleware.RequirePermission(s.az, PermWrite)).Post("/notes", handler.Handle(s.create))
	reader := r.With(middleware.RequireAny(s.az, PermRead, PermReadAny))
	reader.Get("/notes", handler.Handle(s.list))
	reader.Get("/notes/{id}", handler.Handle(s.get))
	return r, nil
}

func (s *service) create(r *http.Request) (any, error) {
	var body struct {
		Text string `json:"text"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Text == "" {
		return nil, errorz.BadRequest().WithMessage("text is required")
	}
	tenant, owner, err := caller(r.Context())
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	n := Note{ID: strconv.Itoa(len(s.notes) + 1), TenantID: tenant, OwnerID: owner, Text: body.Text}
	s.notes = append(s.notes, n)
	return response.Created(n), nil
}

func (s *service) list(r *http.Request) (any, error) {
	tenant, owner, err := caller(r.Context())
	if err != nil {
		return nil, err
	}
	anyOwner := s.az.Can(r.Context(), PermReadAny)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []Note{}
	for _, n := range s.notes {
		if n.TenantID == tenant && (anyOwner || n.OwnerID == owner) {
			out = append(out, n)
		}
	}
	return out, nil
}

// get answers 404 for a note in another tenant, or another owner's note
// without notes:read:any: the caller learns nothing about it.
func (s *service) get(r *http.Request) (any, error) {
	tenant, owner, err := caller(r.Context())
	if err != nil {
		return nil, err
	}
	anyOwner := s.az.Can(r.Context(), PermReadAny)
	id := chi.URLParam(r, "id")
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, n := range s.notes {
		if n.ID == id && n.TenantID == tenant && (anyOwner || n.OwnerID == owner) {
			return n, nil
		}
	}
	return nil, errorz.NotFound().WithMessage("note not found")
}

// caller is the token's tenant and subject.
func caller(ctx context.Context) (tenant, owner string, err error) {
	tenant, ok := authz.TenantID(ctx)
	owner = auth.SubjectFromContext(ctx)
	if !ok || owner == "" {
		return "", "", errorz.Forbidden().WithMessage("token carries no tenant or subject")
	}
	return tenant, owner, nil
}

// serviceToken trades the client credentials for a scope:internal token.
// authz calls it only when it refreshes its cached role map.
func (s *service) serviceToken(ctx context.Context) (string, error) {
	body, err := json.Marshal(map[string]string{
		"grant_type": "client_credentials", "client_id": s.cfg.ClientID, "client_secret": s.cfg.ClientSecret,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.IdentityURL+"/v1/auth/token",
		bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	var env struct {
		Data struct {
			AccessToken string `json:"access_token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK || env.Data.AccessToken == "" {
		return "", fmt.Errorf("sampleresource: service token: status %d", resp.StatusCode)
	}
	return env.Data.AccessToken, nil
}
