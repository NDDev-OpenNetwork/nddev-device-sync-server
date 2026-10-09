#!/bin/sh
# First initialization only; the official entrypoint runs this as postgres.
set -eu
# Pass file contents through psql's environment lookup, never command arguments.
export NDS_MIGRATOR_PASSWORD="$(cat /run/secrets/postgres_migrator_password)"
export NDS_RUNTIME_PASSWORD="$(cat /run/secrets/postgres_runtime_password)"
psql --no-psqlrc --set ON_ERROR_STOP=1 --username postgres --dbname nds <<'SQL'
\getenv migrator_password NDS_MIGRATOR_PASSWORD
\getenv runtime_password NDS_RUNTIME_PASSWORD
CREATE ROLE nds_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'migrator_password';
CREATE ROLE nds_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'runtime_password';
REVOKE ALL ON DATABASE nds FROM PUBLIC;
GRANT CONNECT ON DATABASE nds TO nds_migrator, nds_runtime;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
ALTER SCHEMA public OWNER TO nds_migrator;
GRANT USAGE ON SCHEMA public TO nds_runtime;
ALTER DEFAULT PRIVILEGES FOR ROLE nds_migrator IN SCHEMA public GRANT SELECT ON TABLES TO nds_runtime;
ALTER ROLE nds_runtime SET statement_timeout = '15s';
ALTER ROLE nds_runtime SET lock_timeout = '3s';
ALTER ROLE nds_runtime SET idle_in_transaction_session_timeout = '15s';
ALTER ROLE nds_migrator SET statement_timeout = '45s';
ALTER ROLE nds_migrator SET lock_timeout = '5s';
SQL
unset NDS_MIGRATOR_PASSWORD NDS_RUNTIME_PASSWORD
