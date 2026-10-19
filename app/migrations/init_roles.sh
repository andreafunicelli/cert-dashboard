#!/bin/sh
# Executed by postgres' first-start entrypoint. Never echo secret contents.
set -eu
APP_DB_PASSWORD=$(cat /run/secrets/db_password)
if [ -z "$APP_DB_PASSWORD" ]; then
  printf '%s\n' 'db_password: required non-empty app-role password' >&2
  exit 1
fi
export APP_DB_PASSWORD
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --no-psqlrc --set ON_ERROR_STOP=1 <<'SQL'
\getenv app_password APP_DB_PASSWORD
CREATE ROLE app_role LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO app_role;
SQL
unset APP_DB_PASSWORD
