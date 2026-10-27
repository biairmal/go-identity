package testkit

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// OIDCUser is who the fake provider signs in: the claims of its ID token.
type OIDCUser struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// OIDC is a fake OpenID Connect provider on a local port: discovery, JWKS,
// authorize and token endpoints, enough for the authorization code flow
// with PKCE. Authorize signs in whoever SignInAs last named, without a
// consent screen, so a test drives the whole redirect chain over HTTP and
// never reaches the real provider.
type OIDC struct {
	// URL is the issuer, the discovery base to configure.
	URL          string
	clientID     string
	clientSecret string
	key          *rsa.PrivateKey
	mu           sync.Mutex
	user         OIDCUser
	grants       map[string]oidcGrant
}

// oidcGrant is an issued authorization code waiting for the token call.
type oidcGrant struct {
	user      OIDCUser
	nonce     string
	challenge string
	redirect  string
}

// oidcKID is the key ID of the fake's only signing key.
const oidcKID = "fake-oidc"

// NewOIDC starts a fake provider that accepts one client.
func NewOIDC(t *testing.T, clientID, clientSecret string) *OIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("testkit: oidc key: %v", err)
	}
	o := &OIDC{clientID: clientID, clientSecret: clientSecret, key: key, grants: map[string]oidcGrant{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", o.discovery)
	mux.HandleFunc("GET /jwks", o.jwks)
	mux.HandleFunc("GET /authorize", o.authorize)
	mux.HandleFunc("POST /token", o.token)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	o.URL = srv.URL
	return o
}

// SignInAs sets who the next authorize request signs in.
func (o *OIDC) SignInAs(u OIDCUser) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.user = u
}

func (o *OIDC) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                o.URL,
		"authorization_endpoint":                o.URL + "/authorize",
		"token_endpoint":                        o.URL + "/token",
		"jwks_uri":                              o.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
	})
}

func (o *OIDC) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := o.key.PublicKey
	writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": oidcKID,
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize issues a code for the current user and redirects back with it.
func (o *OIDC) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != o.clientID || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("redirect_uri") == "" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	code := b64(randomBytes())
	o.mu.Lock()
	o.grants[code] = oidcGrant{
		user: o.user, nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"),
	}
	o.mu.Unlock()
	back, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	bq := back.Query()
	bq.Set("code", code)
	bq.Set("state", q.Get("state"))
	back.RawQuery = bq.Encode()
	// The fake sends the browser wherever the client under test asked, like a
	// real provider does for a registered redirect URI.
	http.Redirect(w, r, back.String(), http.StatusFound) //nolint:gosec // see above
}

// token redeems a code once, checking the client, the redirect URI and the
// PKCE verifier, and answers with a signed ID token.
func (o *OIDC) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != o.clientID || secret != o.clientSecret {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_client"})
		return
	}
	o.mu.Lock()
	g, found := o.grants[r.PostForm.Get("code")]
	delete(o.grants, r.PostForm.Get("code"))
	o.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !found || b64(sum[:]) != g.challenge || r.PostForm.Get("redirect_uri") != g.redirect {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant"})
		return
	}
	idToken, err := o.sign(&g)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "server_error"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": b64(randomBytes()), "token_type": "Bearer", "expires_in": 3600, "id_token": idToken,
	})
}

// sign builds the RS256 ID token for a redeemed grant.
func (o *OIDC) sign(g *oidcGrant) (string, error) {
	now := time.Now()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": oidcKID, "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": o.URL, "sub": g.user.Subject, "aud": o.clientID,
		"iat": now.Unix(), "exp": now.Add(time.Hour).Unix(), "nonce": g.nonce,
		"email": g.user.Email, "email_verified": g.user.EmailVerified, "name": g.user.Name,
	})
	if err != nil {
		return "", err
	}
	signing := b64(header) + "." + b64(claims)
	digest := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, o.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signing + "." + b64(sig), nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// randomBytes is 32 random bytes for codes and opaque tokens.
func randomBytes() []byte {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // never fails: crypto/rand aborts the process instead
	return b
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, "%s", b)
}
