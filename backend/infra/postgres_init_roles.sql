-- Idempotent PostgreSQL runtime role provisioning for JYXIA Etapa 3.2+ / 3.3.2.
-- Usage with psql:
--   psql -v ON_ERROR_STOP=1 -v jyxia_app_password='...' -v jyxia_worker_password='...' -f postgres_init_roles.sql
--
-- Separation of duties:
--   1. The migration owner (current bootstrap/owner role) owns schema DDL and SECURITY DEFINER functions.
--   2. The HTTP API runtime role `jyxia_app` is strictly NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION.
--   3. The background worker role `jyxia_worker` is strictly NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION
--      and receives EXECUTE only on scoped queue/lease SECURITY DEFINER functions (zero direct table grants).
--   4. All table/function GRANTs are applied/refreshed by Alembic migrations 0003-0007.

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

        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_worker') THEN
            CREATE ROLE jyxia_worker
                LOGIN
                PASSWORD %L
                NOSUPERUSER
                NOCREATEDB
                NOCREATEROLE
                NOINHERIT
                NOREPLICATION
                NOBYPASSRLS;
        ELSE
            ALTER ROLE jyxia_worker
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
        EXECUTE format('GRANT CONNECT ON DATABASE %%I TO jyxia_worker', current_database());
    END
    $role_init$;
    $$,
    :'jyxia_app_password',
    :'jyxia_app_password',
    :'jyxia_worker_password',
    :'jyxia_worker_password'
) \gexec

REVOKE CREATE ON SCHEMA public FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM jyxia_app;
GRANT USAGE ON SCHEMA public TO jyxia_app;
REVOKE ALL ON SCHEMA public FROM jyxia_worker;
GRANT USAGE ON SCHEMA public TO jyxia_worker;
