# Database backup and restore

The `backup` service (`deploy/compose/docker-compose.yaml`, `vps` profile) runs
`pg_dump -Fc` against the `app` database once a day, writing timestamped dumps into the
`backups` named volume, then deletes dumps older than `BACKUP_KEEP_DAYS` (default 7,
`deploy/compose/.env.example`). It uses the same `postgres:16-alpine` image as the
`postgres` service, so `pg_dump`'s version always matches the server.

## List available dumps

```bash
docker compose --profile vps run --rm -v go-identity_backups:/backups --entrypoint sh postgres \
  -c 'ls -la /backups'
```

(or, simpler, exec into the running `backup` container: `docker compose --profile vps exec backup ls -la /backups`.)

## Restore a dump into an empty database

Run this against a **fresh** database — `pg_restore` with `-Fc` expects the target schema to
not already contain the objects it's about to create.

1. Create the empty database and the `identity` role/schema the same way a fresh VPS is
   bootstrapped (`deploy/sql/bootstrap.sql`), or just create an empty database if restoring
   onto a server that already has the `identity` role:
   ```bash
   createdb -U postgres -h <host> restored_app
   ```
2. Restore the dump:
   ```bash
   pg_restore -h <host> -U postgres -d restored_app --no-owner --clean --if-exists \
     /path/to/app-20261028-030000.dump
   ```
   - `--clean --if-exists` is a no-op against a truly empty database and harmless otherwise.
   - `--no-owner` avoids failing on roles that don't exist on the restore target; the app
     connects through the `identity` role regardless of which role owns the objects.
3. Confirm the `identity` schema came back:
   ```bash
   psql -h <host> -U postgres -d restored_app -c '\dt identity.*'
   ```

From inside the Compose network, swap `-h <host>` for `-h postgres` and run the commands from a
container that mounts the `backups` volume (e.g. `docker compose --profile vps exec backup sh`).

## Out of scope

Off-host copies of the dumps and Helm-based deploys (clusters use their platform's backup
mechanism) are not covered here — see T9.4 in the implementation plan.
