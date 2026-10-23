-- Creates the identity schema and the role that owns it. Run once per
-- environment with admin credentials, outside the app:
--
--   psql -v identity_password='...' -d app -f deploy/sql/bootstrap.sql
--
-- Afterwards the app connects as `identity`, whose search_path is `identity`,
-- so code and migrations use unqualified table names.

SELECT format('CREATE ROLE identity LOGIN PASSWORD %L', :'identity_password')
WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'identity')
\gexec

CREATE SCHEMA IF NOT EXISTS identity AUTHORIZATION identity;
ALTER ROLE identity SET search_path = identity;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
