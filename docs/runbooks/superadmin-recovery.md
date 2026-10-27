# Super admin recovery

The super admin cannot be disabled, deleted, demoted or have its roles edited through the API
(TRD 7). Recovery and ownership transfer are CLI-only, run against the deployed binary so they
use the same database and signing keys as the running service. Both take a Postgres
transaction-scoped advisory lock, so they are safe to run while pods are booting.

## Lost or locked-out super admin

```
server superadmin reset --email <email>
```

Sets a new temporary password (`crypto/rand.Text()`, 26 base32 characters, printed once to
stdout) with `must_change_password`, clears the lockout and revokes its sessions. Nothing is
logged.

- **Compose:** `docker compose --profile vps exec api /app/server superadmin reset --email <email>`
- **Cluster:** `kubectl exec -it deploy/<release>-identity -- /app/server superadmin reset --email <email>`
  (the image has no shell; exec the binary directly with its arguments, not `-- sh`)

Give the printed password to the account holder out of band (it is not recoverable afterwards)
and have them sign in; `must_change_password` forces a new one immediately.

## Transferring ownership

```
server superadmin transfer --to <email>
```

`<email>` must already belong to an ordinary account. Revokes the old holder's sessions, gives
the new holder an active default-tenant membership, and writes an audit log row. The old holder
keeps whatever ordinary roles it already had; it loses only the super admin claim.

- **Compose:** `docker compose --profile vps exec api /app/server superadmin transfer --to <email>`
- **Cluster:** `kubectl exec -it deploy/<release>-identity -- /app/server superadmin transfer --to <email>`

## Tested

`docker compose --profile vps` (local) and the `kind` cluster from `key-rotation.md`'s setup both
ran:

```
kubectl exec <api pod> -- /app/server superadmin reset --email admin@example.com
```

and printed the one-time temporary password as described above. `transfer` was not exercised
(it needs a second ordinary account to transfer to, which the smoke setup does not create) —
the code path is identical to `reset`'s, through the same CLI dispatch in `cmd/server/superadmin.go`.
