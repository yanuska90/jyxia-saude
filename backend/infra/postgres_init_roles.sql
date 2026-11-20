-- Idempotent PostgreSQL runtime role provisioning for JYXIA Etapa 3.2.
-- Usage with psql:
--   psql -v ON_ERROR_STOP=1 -v jyxia_app_password='...' -f postgres_init_roles.sql
--
-- Separation of duties:
--   1. The migration owner (current bootstrap/owner role) owns schema DDL and SECURITY DEFINER functions.
--   2. The runtime role `jyxia_app` is strictly NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION.
--   3. All table/function GRANTs for `jyxia_app` are applied/refreshed by Alembic migration 0003.

SELECT format(
    $$
    DO $role_init$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
            CREATE ROLE jyxia_app
                LOGIN
                PASSWORD %L
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOINHERIT
                NOREPLICATION
                NOBYPASSRLS;
        ELSE
            ALTER ROLE jyxia_app
                WITH LOGIN
                PASSWORD %L
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOINHERIT
                NOREPLICATION
                NOBYPASSRLS;
        END IF;

        EXECUTE format('GRANT CONNECT ON DATABASE %%I TO jyxia_app', current_database());
    END
    $role_init$;
    $$,
    :'jyxia_app_password',
    :'jyxia_app_password'
) \gexec

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM jyxia_app;
GRANT USAGE ON SCHEMA public TO jyxia_app;
