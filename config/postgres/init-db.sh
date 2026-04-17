#!/usr/bin/env bash
set -euo pipefail

HOST="${POSTGRES_HOST:-host.docker.internal}"
PORT="${POSTGRES_PORT:-15432}"
ADMIN_USER="${POSTGRES_ADMIN_USER:-postgres}"
ROLE="${DB_USER:-superset}"
ROLE_PASS="${DB_PASS:-superset}"
DBNAME="${DB_NAME:-superset}"
POSTGRES_USER_NAME="${POSTGRES_USER_NAME:-postgres}"

export PGPASSWORD="${POSTGRES_ADMIN_PASSWORD:-securepassword123}"

PSQL=(psql -h "$HOST" -p "$PORT" -U "$ADMIN_USER" -v ON_ERROR_STOP=1)

echo "init-db: connecting to $HOST:$PORT as $ADMIN_USER"

role_exists="$("${PSQL[@]}" -d postgres -tAc "SELECT 1 FROM pg_roles WHERE rolname = '$ROLE'")"
if [[ "$role_exists" != "1" ]]; then
  "${PSQL[@]}" -d postgres -c "CREATE ROLE \"$ROLE\" LOGIN PASSWORD '$ROLE_PASS'"
fi

db_exists="$("${PSQL[@]}" -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = '$DBNAME'")"
if [[ "$db_exists" != "1" ]]; then
  "${PSQL[@]}" -d postgres -c "CREATE DATABASE \"$DBNAME\" OWNER \"$ROLE\""
fi

# Explicit privileges for postgres user, useful if it is not superuser
"${PSQL[@]}" -d postgres -c "GRANT ALL PRIVILEGES ON DATABASE \"$DBNAME\" TO \"$POSTGRES_USER_NAME\""

"${PSQL[@]}" -d "$DBNAME" <<SQL
GRANT ALL ON SCHEMA public TO "$POSTGRES_USER_NAME";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "$POSTGRES_USER_NAME";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "$POSTGRES_USER_NAME";
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO "$POSTGRES_USER_NAME";

ALTER DEFAULT PRIVILEGES FOR ROLE "$ROLE" IN SCHEMA public
  GRANT ALL PRIVILEGES ON TABLES TO "$POSTGRES_USER_NAME";

ALTER DEFAULT PRIVILEGES FOR ROLE "$ROLE" IN SCHEMA public
  GRANT ALL PRIVILEGES ON SEQUENCES TO "$POSTGRES_USER_NAME";

ALTER DEFAULT PRIVILEGES FOR ROLE "$ROLE" IN SCHEMA public
  GRANT ALL PRIVILEGES ON FUNCTIONS TO "$POSTGRES_USER_NAME";
SQL

echo "init-db: done ($DBNAME owned by $ROLE, $POSTGRES_USER_NAME also granted full access)"