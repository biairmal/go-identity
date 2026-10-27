# Key rotation

Signing keys live in `modules.auth.token.signing_keys_dir` (`SIGNING_KEYS_DIR`, default
`/etc/identity/keys`): one PEM per `kid`, plus `keys.yaml` naming the active, next and retiring
`kid`s. Every pod mounts the same files (TRD 6), so rotation is "change the files, let every pod
pick them up" — never signing out a user, because refresh tokens are not JWTs.

`GET /.well-known/jwks.json` publishes `next`, `active` and `retiring` keys with
`Cache-Control: max-age=300`. go-sdk's JWKS client on resource services refetches on an unknown
`kid` (with a cooldown), so they need no restart either.

## Steps

1. **Generate the new key.**
   ```bash
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out <kid>.pem
   ```
   `<kid>` is free-form and only needs to be unique across files still listed in `keys.yaml`
   (`scripts/gen-dev-keys.sh` uses `YYYY-MM-<suffix>`).

2. **Add it as `next` (published, not signing).** Update `keys.yaml` and redeploy the Secret:
   ```yaml
   active: 2026-10-a
   next: [2026-11-a]
   retiring: []
   ```
   - Compose: edit the files under the host path mounted at `./keys` (see
     `deploy/compose/docker-compose.yaml`), then `docker compose --profile vps restart api worker`.
   - Cluster: update the Secret referenced by `signingKeys.existingSecret`
     (`kubectl create secret generic <name> --from-file=./keys -o yaml --dry-run=client |
     kubectl apply -f -`), then roll the deployments so every pod remounts it:
     `kubectl rollout restart deployment/<release>-identity deployment/<release>-identity-worker`.
   - Confirm it is live: `curl https://<host>/.well-known/jwks.json | jq '.keys[].kid'` lists the
     new `kid`.

3. **Wait one JWKS cache period** (5 minutes, `max-age=300`) so every resource service has had a
   chance to fetch the new key before anything signs with it.

4. **Promote it to `active`, retire the old one.**
   ```yaml
   active: 2026-11-a
   next: []
   retiring: [2026-10-a]
   ```
   Redeploy the same way as step 2. New tokens now carry `kid: 2026-11-a`.

5. **Keep the retiring key published for `access_ttl` plus a margin** (at least 20 minutes for the
   default 15-minute `access_ttl`) so tokens already issued with it still verify. Only then:

6. **Retire it for good.**
   ```yaml
   active: 2026-11-a
   next: []
   retiring: []
   ```
   Delete `2026-10-a.pem` once this has been live for one more JWKS cache period (so no client is
   mid-fetch of the key you are about to remove), then redeploy.

## Tested on kind

Installed the chart on a `kind` cluster (plain in-cluster Postgres, `DB_SSLMODE=disable`;
`APP_ENV=staging` because of the open F2 follow-up in `docs/DECISIONS.md` — no production
`Mailer` yet, so the worker refuses `APP_ENV=production` until that lands) with one `next` key
added to the Secret after `install`:

```bash
kind create cluster --name t74
docker build -t go-identity:kind .
kind load docker-image go-identity:kind --name t74
# Postgres + deploy/sql/bootstrap.sql, then:
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out 2026-10-a.pem
cat > keys.yaml <<'YAML'
active: 2026-10-a
next: []
retiring: []
YAML
kubectl create secret generic identity-keys --from-file=2026-10-a.pem --from-file=keys.yaml
kubectl create secret generic identity-secrets --from-literal=DB_PASSWORD=identity \
  --from-literal=SUPER_ADMIN_EMAIL=admin@example.com --from-literal=SUPER_ADMIN_PASSWORD='...' \
  --from-literal=EMAIL_ENCRYPTION_KEY="$(openssl rand -base64 32)" \
  --from-literal=EMAIL_BLIND_INDEX_KEY="$(openssl rand -base64 32)"
helm install identity deploy/helm/identity \
  --set image.repository=go-identity --set image.tag=kind --set image.pullPolicy=Never \
  --set signingKeys.existingSecret=identity-keys --set secret.existingSecret=identity-secrets \
  --set config.DB_HOST=postgres --set config.DB_SSLMODE=disable --set config.APP_ENV=staging \
  --set autoscaling.enabled=false --set replicaCount=1 --wait
```

`curl http://identity-identity/.well-known/jwks.json` from inside the cluster returned one key
(`2026-10-a`). Generating `2026-11-a.pem`, rewriting `keys.yaml` to `next: [2026-11-a]`, replacing
the Secret and `kubectl rollout restart deployment/identity-identity
deployment/identity-identity-worker` made both pods come back `Running` and
`/.well-known/jwks.json` list both `2026-11-a` and `2026-10-a` — the rotation step a resource
service would see. `helm upgrade` with the same values afterwards ran the `migrate` Job again as
a pre-upgrade hook and completed cleanly against the now-migrated database (steps 4-6 are the
same Secret-and-restart mechanics, not re-run here).
