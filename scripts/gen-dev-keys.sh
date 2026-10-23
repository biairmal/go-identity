#!/usr/bin/env bash
# Generates a local signing key for development, so `make run` can start.
#
# Real environments mount these files as a secret and never generate them at
# startup: every pod must load the same key, or a token signed by one pod
# fails on another. Rotating is documented in docs/runbooks/key-rotation.md
# (T7.4); in short, add the new key under `next`, wait one JWKS cache period,
# then make it `active` and move the old one to `retiring`.
set -euo pipefail

dir="${1:-./keys}"
kid="${2:-$(date +%Y-%m)-dev}"

if [[ -f "$dir/$kid.pem" ]]; then
    echo "keys: $dir/$kid.pem already exists, leaving it alone"
    exit 0
fi

mkdir -p "$dir"
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "$dir/$kid.pem" 2>/dev/null
chmod 600 "$dir/$kid.pem"

cat > "$dir/keys.yaml" <<YAML
# Which key signs new tokens, and which are published alongside it.
active: $kid
next: []
retiring: []
YAML

echo "keys: wrote $dir/$kid.pem and $dir/keys.yaml"
echo "keys: set SIGNING_KEYS_DIR=$dir (see .env.example)"
