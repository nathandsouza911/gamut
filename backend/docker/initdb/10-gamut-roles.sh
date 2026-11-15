#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Creates GAMUT's two database roles. The postgres image runs every file in
# /docker-entrypoint-initdb.d once, on first start with an empty data directory,
# as the bootstrap superuser ($POSTGRES_USER) against $POSTGRES_DB.
# docker-compose.yml mounts this directory there; CI runs this script with psql.
#
#   gamut_owner  owns the database, the public schema and every table. Only
#                Alembic migrations connect as this role (GAMUT_MIGRATE_DATABASE_URL).
#   gamut_app    the role web and worker connect as (GAMUT_DATABASE_URL). Table
#                grants are made by migration 0001: full DML everywhere except
#                audit_events (SELECT and INSERT only), and no TRUNCATE anywhere.
set -e
: "${GAMUT_OWNER_DB_PASSWORD:?set GAMUT_OWNER_DB_PASSWORD}"
: "${GAMUT_APP_DB_PASSWORD:?set GAMUT_APP_DB_PASSWORD}"

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v db="$POSTGRES_DB" \
  -v owner_pw="$GAMUT_OWNER_DB_PASSWORD" \
  -v app_pw="$GAMUT_APP_DB_PASSWORD" <<'SQL'
CREATE ROLE gamut_owner LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'owner_pw';
CREATE ROLE gamut_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'app_pw';
ALTER DATABASE :"db" OWNER TO gamut_owner;
ALTER SCHEMA public OWNER TO gamut_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT, TEMPORARY ON DATABASE :"db" TO gamut_app;
SQL
