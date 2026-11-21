"""Harden SECURITY DEFINER audit functions, enable FORCE RLS and isolate identity/session tables.

Revision ID: 20261121_0004
Revises: 20261120_0003
Create Date: 2026-11-21 18:45:00+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20261121_0004"
down_revision = "20261120_0003"
branch_labels = None
depends_on = None

_FORCE_RLS_TENANT_TABLES: tuple[str, ...] = (
    "organization_memberships",
    "document_cases",
    "documents",
    "document_versions",
    "processing_runs",
    "extracted_fields",
    "evidence_references",
    "human_reviews",
    "audit_events",
)


def _upgrade_pg_security_definer_and_rls() -> None:
    # 1. Harden jyxia_append_audit_event with transaction context, active organization,
    #    authenticated actor context, and active membership validation.
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_append_audit_event(
                p_id varchar,
                p_organization_id varchar,
                p_schema_version varchar,
                p_sequence_number integer,
                p_actor_user_id varchar,
                p_event_type varchar,
                p_target_entity_type varchar,
                p_target_entity_id varchar,
                p_payload_json text,
                p_prev_event_hash varchar,
                p_event_hash varchar,
                p_created_at timestamptz
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_ctx_org varchar;
                v_ctx_user varchar;
                v_org_exists varchar;
                v_actor_active boolean;
                v_membership_status varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                v_ctx_org := NULLIF(current_setting('app.current_organization_id', true), '');
                v_ctx_user := NULLIF(current_setting('app.current_user_id', true), '');

                IF v_ctx_org IS NULL THEN
                    RAISE EXCEPTION 'Audit append rejected: missing active organization context';
                END IF;

                IF p_organization_id IS NULL OR p_organization_id <> v_ctx_org THEN
                    RAISE EXCEPTION 'Audit append rejected: organization_id (%) does not match active context (%)',
                        COALESCE(p_organization_id, '<null>'), v_ctx_org;
                END IF;

                IF p_schema_version IS NULL OR p_schema_version <> 'jyxia.audit.v1' THEN
                    RAISE EXCEPTION 'Audit append rejected: invalid schema_version';
                END IF;

                IF p_event_type IS NULL OR length(trim(p_event_type)) < 2 THEN
                    RAISE EXCEPTION 'Audit append rejected: invalid event_type';
                END IF;

                IF p_target_entity_type IS NULL OR length(trim(p_target_entity_type)) < 2 THEN
                    RAISE EXCEPTION 'Audit append rejected: invalid target_entity_type';
                END IF;

                IF p_target_entity_id IS NULL OR length(trim(p_target_entity_id)) < 1 THEN
                    RAISE EXCEPTION 'Audit append rejected: invalid target_entity_id';
                END IF;

                IF p_prev_event_hash IS NULL OR p_prev_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Audit append rejected: invalid prev_event_hash format';
                END IF;

                IF p_event_hash IS NULL OR p_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Audit append rejected: invalid event_hash format';
                END IF;

                SELECT o.id INTO v_org_exists
                FROM public.organizations AS o
                WHERE o.id = p_organization_id
                  AND o.status = 'active'
                FOR UPDATE;

                IF v_org_exists IS NULL THEN
                    RAISE EXCEPTION 'Active organization % does not exist for audit append', p_organization_id;
                END IF;

                IF session_user = 'jyxia_app' THEN
                    IF p_actor_user_id IS NULL OR v_ctx_user IS NULL THEN
                        RAISE EXCEPTION 'Audit append rejected: runtime role requires authenticated actor_user_id and user context';
                    END IF;
                END IF;

                IF p_actor_user_id IS NOT NULL OR v_ctx_user IS NOT NULL THEN
                    IF p_actor_user_id IS NULL OR v_ctx_user IS NULL OR p_actor_user_id <> v_ctx_user THEN
                        RAISE EXCEPTION 'Audit append rejected: actor_user_id (%) does not match active user context (%)',
                            COALESCE(p_actor_user_id, '<null>'), COALESCE(v_ctx_user, '<null>');
                    END IF;

                    SELECT u.is_active INTO v_actor_active
                    FROM public.users AS u
                    WHERE u.id = p_actor_user_id;

                    IF v_actor_active IS DISTINCT FROM TRUE THEN
                        RAISE EXCEPTION 'Audit append rejected: actor % does not exist or is inactive', p_actor_user_id;
                    END IF;

                    SELECT om.status INTO v_membership_status
                    FROM public.organization_memberships AS om
                    WHERE om.organization_id = p_organization_id
                      AND om.user_id = p_actor_user_id;

                    IF v_membership_status IS NULL THEN
                        RAISE EXCEPTION 'Audit append rejected: actor % has no membership in organization %',
                            p_actor_user_id, p_organization_id;
                    END IF;

                    IF v_membership_status <> 'active' THEN
                        RAISE EXCEPTION 'Audit append rejected: actor % membership in organization % is % (not active)',
                            p_actor_user_id, p_organization_id, v_membership_status;
                    END IF;
                END IF;

                SELECT COALESCE(MAX(ae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = p_organization_id;

                IF p_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Audit sequence mismatch: expected %, got %', v_expected_seq, p_sequence_number;
                END IF;

                IF v_expected_seq = 1 THEN
                    v_expected_prev := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_expected_prev
                    FROM public.audit_events AS ae
                    WHERE ae.organization_id = p_organization_id
                      AND ae.sequence_number = v_expected_seq - 1;
                END IF;

                IF p_prev_event_hash <> v_expected_prev THEN
                    RAISE EXCEPTION 'Audit prev_event_hash mismatch for sequence %', p_sequence_number;
                END IF;

                INSERT INTO public.audit_events (
                    id,
                    organization_id,
                    schema_version,
                    sequence_number,
                    actor_user_id,
                    event_type,
                    target_entity_type,
                    target_entity_id,
                    payload_json,
                    prev_event_hash,
                    event_hash,
                    created_at
                ) VALUES (
                    p_id,
                    p_organization_id,
                    p_schema_version,
                    p_sequence_number,
                    p_actor_user_id,
                    p_event_type,
                    p_target_entity_type,
                    p_target_entity_id,
                    p_payload_json::jsonb,
                    p_prev_event_hash,
                    p_event_hash,
                    p_created_at
                );
            END;
            $$;
            """
        )
    )

    # 2. Harden jyxia_append_security_event with context, user, org, and membership checks.
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_append_security_event(
                p_id varchar,
                p_schema_version varchar,
                p_sequence_number integer,
                p_event_type varchar,
                p_outcome varchar,
                p_user_id varchar,
                p_organization_id varchar,
                p_issuer varchar,
                p_subject_hash varchar,
                p_session_id varchar,
                p_correlation_id varchar,
                p_reason_code varchar,
                p_payload_json text,
                p_prev_event_hash varchar,
                p_event_hash varchar,
                p_created_at timestamptz
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_ctx_org varchar;
                v_ctx_user varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                v_ctx_org := NULLIF(current_setting('app.current_organization_id', true), '');
                v_ctx_user := NULLIF(current_setting('app.current_user_id', true), '');

                IF p_schema_version IS NULL OR p_schema_version <> 'jyxia.sec_audit.v1' THEN
                    RAISE EXCEPTION 'Security audit append rejected: invalid schema_version';
                END IF;

                IF p_outcome IS NULL OR p_outcome NOT IN ('success', 'denied', 'failure') THEN
                    RAISE EXCEPTION 'Security audit append rejected: invalid outcome';
                END IF;

                IF p_event_type IS NULL OR length(trim(p_event_type)) < 2 THEN
                    RAISE EXCEPTION 'Security audit append rejected: invalid event_type';
                END IF;

                IF p_reason_code IS NULL OR length(trim(p_reason_code)) < 2 THEN
                    RAISE EXCEPTION 'Security audit append rejected: invalid reason_code';
                END IF;

                IF p_prev_event_hash IS NULL OR p_prev_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Security audit append rejected: invalid prev_event_hash';
                END IF;

                IF p_event_hash IS NULL OR p_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Security audit append rejected: invalid event_hash';
                END IF;

                IF p_organization_id IS NOT NULL THEN
                    IF v_ctx_org IS NULL OR p_organization_id <> v_ctx_org THEN
                        RAISE EXCEPTION 'Security audit append rejected: organization_id (%) does not match active context (%)',
                            p_organization_id, COALESCE(v_ctx_org, '<null>');
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM public.organizations AS o WHERE o.id = p_organization_id) THEN
                        RAISE EXCEPTION 'Security audit append rejected: organization % does not exist', p_organization_id;
                    END IF;
                END IF;

                IF p_user_id IS NOT NULL THEN
                    IF v_ctx_user IS NULL OR p_user_id <> v_ctx_user THEN
                        RAISE EXCEPTION 'Security audit append rejected: user_id (%) does not match active context (%)',
                            p_user_id, COALESCE(v_ctx_user, '<null>');
                    END IF;
                    IF NOT EXISTS (SELECT 1 FROM public.users AS u WHERE u.id = p_user_id) THEN
                        RAISE EXCEPTION 'Security audit append rejected: user % does not exist', p_user_id;
                    END IF;
                END IF;

                IF p_organization_id IS NOT NULL AND p_user_id IS NOT NULL THEN
                    IF NOT EXISTS (
                        SELECT 1
                        FROM public.organization_memberships AS om
                        WHERE om.organization_id = p_organization_id
                          AND om.user_id = p_user_id
                    ) THEN
                        RAISE EXCEPTION 'Security audit append rejected: user % has no membership record in organization %',
                            p_user_id, p_organization_id;
                    END IF;
                END IF;

                PERFORM pg_advisory_xact_lock(9021042);

                SELECT COALESCE(MAX(sae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.security_auth_events AS sae;

                IF p_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Security audit sequence mismatch: expected %, got %', v_expected_seq, p_sequence_number;
                END IF;

                IF v_expected_seq = 1 THEN
                    v_expected_prev := repeat('0', 64);
                ELSE
                    SELECT sae.event_hash INTO v_expected_prev
                    FROM public.security_auth_events AS sae
                    WHERE sae.sequence_number = v_expected_seq - 1;
                END IF;

                IF p_prev_event_hash <> v_expected_prev THEN
                    RAISE EXCEPTION 'Security audit prev_event_hash mismatch for sequence %', p_sequence_number;
                END IF;

                INSERT INTO public.security_auth_events (
                    id,
                    schema_version,
                    sequence_number,
                    event_type,
                    outcome,
                    user_id,
                    organization_id,
                    issuer,
                    subject_hash,
                    session_id,
                    correlation_id,
                    reason_code,
                    payload_json,
                    prev_event_hash,
                    event_hash,
                    created_at
                ) VALUES (
                    p_id,
                    p_schema_version,
                    p_sequence_number,
                    p_event_type,
                    p_outcome,
                    p_user_id,
                    p_organization_id,
                    p_issuer,
                    p_subject_hash,
                    p_session_id,
                    p_correlation_id,
                    p_reason_code,
                    p_payload_json::jsonb,
                    p_prev_event_hash,
                    p_event_hash,
                    p_created_at
                );
            END;
            $$;
            """
        )
    )

    # 3. Apply FORCE ROW LEVEL SECURITY across tenant-scoped tables.
    for table_name in _FORCE_RLS_TENANT_TABLES:
        op.execute(sa.text(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY;"))

    # 4. Enable + Force RLS on sensitive identity and session tables (auth_sessions, external_identities, oidc_auth_states).
    op.execute(sa.text("ALTER TABLE auth_sessions ENABLE ROW LEVEL SECURITY;"))
    op.execute(sa.text("ALTER TABLE auth_sessions FORCE ROW LEVEL SECURITY;"))
    op.execute(
        sa.text(
            """
            CREATE POLICY p_auth_sessions_isolation ON auth_sessions
            USING (
                (
                    NULLIF(current_setting('app.current_session_token_hash', true), '') IS NOT NULL
                    AND session_token_hash = NULLIF(current_setting('app.current_session_token_hash', true), '')
                )
                OR (
                    NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
                    AND user_id = NULLIF(current_setting('app.current_user_id', true), '')
                )
            )
            WITH CHECK (
                (
                    NULLIF(current_setting('app.current_session_token_hash', true), '') IS NOT NULL
                    AND session_token_hash = NULLIF(current_setting('app.current_session_token_hash', true), '')
                )
                OR (
                    NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
                    AND user_id = NULLIF(current_setting('app.current_user_id', true), '')
                )
            );
            """
        )
    )

    op.execute(sa.text("ALTER TABLE external_identities ENABLE ROW LEVEL SECURITY;"))
    op.execute(sa.text("ALTER TABLE external_identities FORCE ROW LEVEL SECURITY;"))
    op.execute(
        sa.text(
            """
            CREATE POLICY p_external_identities_isolation ON external_identities
            USING (
                (
                    NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
                    AND user_id = NULLIF(current_setting('app.current_user_id', true), '')
                )
                OR (
                    NULLIF(current_setting('app.current_oidc_issuer', true), '') IS NOT NULL
                    AND NULLIF(current_setting('app.current_oidc_subject', true), '') IS NOT NULL
                    AND issuer = NULLIF(current_setting('app.current_oidc_issuer', true), '')
                    AND subject = NULLIF(current_setting('app.current_oidc_subject', true), '')
                )
                OR (
                    NULLIF(current_setting('app.current_session_token_hash', true), '') IS NOT NULL
                    AND EXISTS (
                        SELECT 1
                        FROM public.auth_sessions AS s
                        WHERE s.external_identity_id = external_identities.id
                          AND s.session_token_hash = NULLIF(current_setting('app.current_session_token_hash', true), '')
                    )
                )
            )
            WITH CHECK (
                NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
                AND user_id = NULLIF(current_setting('app.current_user_id', true), '')
            );
            """
        )
    )

    op.execute(sa.text("ALTER TABLE oidc_auth_states ENABLE ROW LEVEL SECURITY;"))
    op.execute(sa.text("ALTER TABLE oidc_auth_states FORCE ROW LEVEL SECURITY;"))
    op.execute(
        sa.text(
            """
            CREATE POLICY p_oidc_auth_states_isolation ON oidc_auth_states
            USING (
                NULLIF(current_setting('app.current_oidc_state_hash', true), '') IS NOT NULL
                AND state_hash = NULLIF(current_setting('app.current_oidc_state_hash', true), '')
            )
            WITH CHECK (
                NULLIF(current_setting('app.current_oidc_state_hash', true), '') IS NOT NULL
                AND state_hash = NULLIF(current_setting('app.current_oidc_state_hash', true), '')
            );
            """
        )
    )

    # 5. Re-apply least-privilege function grants.
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                REVOKE ALL ON FUNCTION public.jyxia_append_audit_event(
                    varchar, varchar, varchar, integer, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_append_security_event(
                    varchar, varchar, integer, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    GRANT EXECUTE ON FUNCTION public.jyxia_append_audit_event(
                        varchar, varchar, varchar, integer, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                    ) TO jyxia_app;
                    GRANT EXECUTE ON FUNCTION public.jyxia_append_security_event(
                        varchar, varchar, integer, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                    ) TO jyxia_app;
                END IF;
            END
            $$;
            """
        )
    )


def _downgrade_pg_security_definer_and_rls() -> None:
    for table_name, policy_name in (
        ("oidc_auth_states", "p_oidc_auth_states_isolation"),
        ("external_identities", "p_external_identities_isolation"),
        ("auth_sessions", "p_auth_sessions_isolation"),
    ):
        op.execute(sa.text(f"DROP POLICY IF EXISTS {policy_name} ON {table_name};"))
        op.execute(sa.text(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY;"))
        op.execute(sa.text(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY;"))

    for table_name in reversed(_FORCE_RLS_TENANT_TABLES):
        op.execute(sa.text(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY;"))

    # Restore revision 0003 function definitions
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_append_audit_event(
                p_id varchar,
                p_organization_id varchar,
                p_schema_version varchar,
                p_sequence_number integer,
                p_actor_user_id varchar,
                p_event_type varchar,
                p_target_entity_type varchar,
                p_target_entity_id varchar,
                p_payload_json text,
                p_prev_event_hash varchar,
                p_event_hash varchar,
                p_created_at timestamptz
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_org_exists varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                SELECT o.id INTO v_org_exists
                FROM public.organizations AS o
                WHERE o.id = p_organization_id
                FOR UPDATE;

                IF v_org_exists IS NULL THEN
                    RAISE EXCEPTION 'Organization % does not exist for audit append', p_organization_id;
                END IF;

                SELECT COALESCE(MAX(ae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = p_organization_id;

                IF p_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Audit sequence mismatch: expected %, got %', v_expected_seq, p_sequence_number;
                END IF;

                IF v_expected_seq = 1 THEN
                    v_expected_prev := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_expected_prev
                    FROM public.audit_events AS ae
                    WHERE ae.organization_id = p_organization_id
                      AND ae.sequence_number = v_expected_seq - 1;
                END IF;

                IF p_prev_event_hash <> v_expected_prev THEN
                    RAISE EXCEPTION 'Audit prev_event_hash mismatch for sequence %', p_sequence_number;
                END IF;

                INSERT INTO public.audit_events (
                    id,
                    organization_id,
                    schema_version,
                    sequence_number,
                    actor_user_id,
                    event_type,
                    target_entity_type,
                    target_entity_id,
                    payload_json,
                    prev_event_hash,
                    event_hash,
                    created_at
                ) VALUES (
                    p_id,
                    p_organization_id,
                    p_schema_version,
                    p_sequence_number,
                    p_actor_user_id,
                    p_event_type,
                    p_target_entity_type,
                    p_target_entity_id,
                    p_payload_json::jsonb,
                    p_prev_event_hash,
                    p_event_hash,
                    p_created_at
                );
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_append_security_event(
                p_id varchar,
                p_schema_version varchar,
                p_sequence_number integer,
                p_event_type varchar,
                p_outcome varchar,
                p_user_id varchar,
                p_organization_id varchar,
                p_issuer varchar,
                p_subject_hash varchar,
                p_session_id varchar,
                p_correlation_id varchar,
                p_reason_code varchar,
                p_payload_json text,
                p_prev_event_hash varchar,
                p_event_hash varchar,
                p_created_at timestamptz
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                PERFORM pg_advisory_xact_lock(9021042);

                SELECT COALESCE(MAX(sae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.security_auth_events AS sae;

                IF p_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Security audit sequence mismatch: expected %, got %', v_expected_seq, p_sequence_number;
                END IF;

                IF v_expected_seq = 1 THEN
                    v_expected_prev := repeat('0', 64);
                ELSE
                    SELECT sae.event_hash INTO v_expected_prev
                    FROM public.security_auth_events AS sae
                    WHERE sae.sequence_number = v_expected_seq - 1;
                END IF;

                IF p_prev_event_hash <> v_expected_prev THEN
                    RAISE EXCEPTION 'Security audit prev_event_hash mismatch for sequence %', p_sequence_number;
                END IF;

                INSERT INTO public.security_auth_events (
                    id,
                    schema_version,
                    sequence_number,
                    event_type,
                    outcome,
                    user_id,
                    organization_id,
                    issuer,
                    subject_hash,
                    session_id,
                    correlation_id,
                    reason_code,
                    payload_json,
                    prev_event_hash,
                    event_hash,
                    created_at
                ) VALUES (
                    p_id,
                    p_schema_version,
                    p_sequence_number,
                    p_event_type,
                    p_outcome,
                    p_user_id,
                    p_organization_id,
                    p_issuer,
                    p_subject_hash,
                    p_session_id,
                    p_correlation_id,
                    p_reason_code,
                    p_payload_json::jsonb,
                    p_prev_event_hash,
                    p_event_hash,
                    p_created_at
                );
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                REVOKE ALL ON FUNCTION public.jyxia_append_audit_event(
                    varchar, varchar, varchar, integer, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_append_security_event(
                    varchar, varchar, integer, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    GRANT EXECUTE ON FUNCTION public.jyxia_append_audit_event(
                        varchar, varchar, varchar, integer, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                    ) TO jyxia_app;
                    GRANT EXECUTE ON FUNCTION public.jyxia_append_security_event(
                        varchar, varchar, integer, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                    ) TO jyxia_app;
                END IF;
            END
            $$;
            """
        )
    )


def upgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _upgrade_pg_security_definer_and_rls()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _downgrade_pg_security_definer_and_rls()
