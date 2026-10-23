#!/bin/sh
# First start only: create the identity schema and role (deploy/sql/bootstrap.sql).
set -e
psql -v ON_ERROR_STOP=1 -v identity_password="$IDENTITY_DB_PASSWORD" \
  -U "$POSTGRES_USER" -d "$POSTGRES_DB" -f /bootstrap/bootstrap.sql
