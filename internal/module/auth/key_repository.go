package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"math/big"

	sdkauth "github.com/biairmal/go-sdk/lib/auth"
	"github.com/biairmal/go-sdk/lib/errorz"
	"github.com/biairmal/go-sdk/lib/sqlkit"

	"github.com/biairmal/go-identity/internal/platform/database"
)

// KeyRepository records which signing keys exist and in which state. Only
// metadata is stored: the private keys stay in the mounted secret, so the
// database never holds anything that can sign a token.
type KeyRepository struct {
	db *sqlkit.DB
}

// NewKeyRepository returns a KeyRepository over db.
func NewKeyRepository(db *sqlkit.DB) *KeyRepository { return &KeyRepository{db: db} }

// Sync records the loaded keys with their statuses and marks any key the
// manifest no longer lists as retired, so an operator can see from the
// database which keys a pod is publishing.
func (r *KeyRepository) Sync(ctx context.Context, keys []sdkauth.PublicKey, statuses map[string]string) error {
	conn := database.Leader(ctx, r.db)
	kids := make([]string, 0, len(keys))
	for i := range keys {
		jwk, err := publicJWK(&keys[i])
		if err != nil {
			return err
		}
		status := statuses[keys[i].KID]
		_, err = conn.ExecContext(ctx,
			`INSERT INTO signing_keys (kid, public_jwk, status, activated_at, updated_at)
			 VALUES ($1, $2, $3, CASE WHEN $3 = 'active' THEN now() END, now())
			 ON CONFLICT (kid) DO UPDATE SET
			     public_jwk = EXCLUDED.public_jwk,
			     status = EXCLUDED.status,
			     activated_at = COALESCE(signing_keys.activated_at, EXCLUDED.activated_at),
			     updated_at = now()`,
			keys[i].KID, jwk, status)
		if err != nil {
			return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: sync signing key")
		}
		kids = append(kids, keys[i].KID)
	}
	_, err := conn.ExecContext(ctx,
		`UPDATE signing_keys SET status = 'retired', updated_at = now()
		 WHERE NOT (kid = ANY($1)) AND status <> 'retired'`, kids)
	if err != nil {
		return errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: retire signing keys")
	}
	return nil
}

// base64URL is the unpadded base64url encoding JWK numbers use.
func base64URL(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// publicJWK encodes one public key as the JWK stored for operators.
func publicJWK(k *sdkauth.PublicKey) ([]byte, error) {
	b, err := json.Marshal(map[string]string{
		"kty": "RSA",
		"kid": k.KID,
		"use": "sig",
		"alg": "RS256",
		"n":   base64URL(k.Key.N.Bytes()),
		"e":   base64URL(big.NewInt(int64(k.Key.E)).Bytes()),
	})
	if err != nil {
		return nil, errorz.Wrap(err).WithCode(errorz.CodeInternal).WithMessage("auth: encode jwk")
	}
	return b, nil
}
