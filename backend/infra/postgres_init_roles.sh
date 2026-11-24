#!/bin/sh
set -eu

: "${JYXIA_APP_DB_PASSWORD:?JYXIA_APP_DB_PASSWORD must be set before initializing PostgreSQL roles.}"
: "${JYXIA_WORKER_DB_PASSWORD:?JYXIA_WORKER_DB_PASSWORD must be set before initializing PostgreSQL roles.}"

psql -v ON_ERROR_STOP=1 \
    --username "$POSTGRES_USER" \
    --dbname "$POSTGRES_DB" \
    -v jyxia_app_password="$JYXIA_APP_DB_PASSWORD" \
    -v jyxia_worker_password="$JYXIA_WORKER_DB_PASSWORD" \
    -f /opt/jyxia/postgres_init_roles.sql
