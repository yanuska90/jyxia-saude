"""Add federated identity, OIDC states, sessions, security audit ledger, RLS and DB role separation.

Revision ID: 20261120_0003
Revises: 20261120_0002
Create Date: 2026-11-20 15:30:00+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20261120_0003"
down_revision = "20261120_0002"
branch_labels = None
depends_on = None

SECURITY_AUDIT_SCHEMA_VERSION = "jyxia.sec_audit.v1"

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

_JSON_VARIANT = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

_TENANT_ISOLATION_TABLES: tuple[str, ...] = (
    "document_cases",
    "documents",
    "document_versions",
    "processing_runs",
    "extracted_fields",
    "evidence_references",
    "human_reviews",
    "audit_events",
    "security_auth_events",
)


def _install_security_audit_and_truncate_triggers(dialect_name: str) -> None:
    if dialect_name == "postgresql":
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_audit_events_no_truncate
                BEFORE TRUNCATE ON audit_events
                FOR EACH STATEMENT EXECUTE FUNCTION jyxia_forbid_audit_event_mutation();
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION jyxia_forbid_security_audit_mutation()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'security_auth_events is append-only; % is not permitted', TG_OP;
                END;
                $$ LANGUAGE plpgsql;
                """
            )
        )
        for op_name, suffix in (
            ("BEFORE UPDATE", "no_update"),
            ("BEFORE DELETE", "no_delete"),
        ):
            op.execute(
                sa.text(
                    f"""
                    CREATE TRIGGER trg_security_auth_events_{suffix}
                    {op_name} ON security_auth_events
                    FOR EACH ROW EXECUTE FUNCTION jyxia_forbid_security_audit_mutation();
                    """
                )
            )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_security_auth_events_no_truncate
                BEFORE TRUNCATE ON security_auth_events
                FOR EACH STATEMENT EXECUTE FUNCTION jyxia_forbid_security_audit_mutation();
                """
            )
        )
    elif dialect_name == "sqlite":
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_security_auth_events_no_update
                BEFORE UPDATE ON security_auth_events
                BEGIN
                    SELECT RAISE(ABORT, 'security_auth_events is append-only; UPDATE is not permitted');
                END;
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_security_auth_events_no_delete
                BEFORE DELETE ON security_auth_events
                BEGIN
                    SELECT RAISE(ABORT, 'security_auth_events is append-only; DELETE is not permitted');
                END;
                """
            )
        )


def _drop_security_audit_and_truncate_triggers(dialect_name: str) -> None:
    if dialect_name == "postgresql":
        op.execute(
            sa.text(
                "DROP TRIGGER IF EXISTS trg_security_auth_events_no_truncate ON security_auth_events;"
            )
        )
        op.execute(
            sa.text(
                "DROP TRIGGER IF EXISTS trg_security_auth_events_no_delete ON security_auth_events;"
            )
        )
        op.execute(
            sa.text(
                "DROP TRIGGER IF EXISTS trg_security_auth_events_no_update ON security_auth_events;"
            )
        )
        op.execute(sa.text("DROP FUNCTION IF EXISTS jyxia_forbid_security_audit_mutation();"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_events_no_truncate ON audit_events;"))
    elif dialect_name == "sqlite":
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_security_auth_events_no_delete;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_security_auth_events_no_update;"))


def _install_pg_security_functions_rls_and_grants() -> None:
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_get_security_audit_head()
            RETURNS TABLE(last_sequence integer, last_event_hash varchar)
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_seq integer;
                v_hash varchar;
            BEGIN
                SELECT COALESCE(MAX(sequence_number), 0) INTO v_seq
                FROM public.security_auth_events;

                IF v_seq = 0 THEN
                    v_hash := repeat('0', 64);
                ELSE
                    SELECT sae.event_hash INTO v_hash
                    FROM public.security_auth_events AS sae
                    WHERE sae.sequence_number = v_seq;
                END IF;

                RETURN QUERY SELECT v_seq, v_hash;
            END;
            $$;
            """
        )
    )

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

    op.execute(sa.text("ALTER TABLE organization_memberships ENABLE ROW LEVEL SECURITY;"))
    op.execute(
        sa.text(
            """
            CREATE POLICY p_org_memberships_tenant_or_self ON organization_memberships
            USING (
                (
                    NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                    AND organization_id = NULLIF(current_setting('app.current_organization_id', true), '')
                )
                OR (
                    NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
                    AND user_id = NULLIF(current_setting('app.current_user_id', true), '')
                )
            )
            WITH CHECK (
                NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                AND organization_id = NULLIF(current_setting('app.current_organization_id', true), '')
            );
            """
        )
    )

    for table_name in _TENANT_ISOLATION_TABLES:
        op.execute(sa.text(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY;"))
        op.execute(
            sa.text(
                f"""
                CREATE POLICY p_{table_name}_tenant_isolation ON {table_name}
                USING (
                    NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                    AND organization_id = NULLIF(current_setting('app.current_organization_id', true), '')
                )
                WITH CHECK (
                    NULLIF(current_setting('app.current_organization_id', true), '') IS NOT NULL
                    AND organization_id = NULLIF(current_setting('app.current_organization_id', true), '')
                );
                """
            )
        )

    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                REVOKE ALL ON FUNCTION public.jyxia_get_security_audit_head() FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_append_audit_event(
                    varchar, varchar, varchar, integer, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_append_security_event(
                    varchar, varchar, integer, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    REVOKE ALL ON SCHEMA public FROM jyxia_app;
                    GRANT USAGE ON SCHEMA public TO jyxia_app;
                    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, jyxia_app;

                    GRANT SELECT ON
                        public.organizations,
                        public.users,
                        public.organization_memberships,
                        public.audit_events,
                        public.security_auth_events
                    TO jyxia_app;

                    GRANT SELECT ON public.external_identities TO jyxia_app;
                    GRANT UPDATE (last_authenticated_at, updated_at) ON public.external_identities TO jyxia_app;

                    GRANT SELECT, INSERT, UPDATE ON
                        public.oidc_auth_states,
                        public.auth_sessions,
                        public.document_cases,
                        public.documents,
                        public.document_versions,
                        public.processing_runs,
                        public.extracted_fields,
                        public.evidence_references,
                        public.human_reviews
                    TO jyxia_app;

                    GRANT EXECUTE ON FUNCTION public.jyxia_get_security_audit_head() TO jyxia_app;
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


def _drop_pg_security_functions_rls_and_grants() -> None:
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM jyxia_app;
                    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM jyxia_app;
                END IF;
            END
            $$;
            """
        )
    )
    for table_name in reversed(_TENANT_ISOLATION_TABLES):
        op.execute(sa.text(f"DROP POLICY IF EXISTS p_{table_name}_tenant_isolation ON {table_name};"))
        op.execute(sa.text(f"ALTER TABLE {table_name} DISABLE ROW LEVEL SECURITY;"))

    op.execute(
        sa.text("DROP POLICY IF EXISTS p_org_memberships_tenant_or_self ON organization_memberships;")
    )
    op.execute(sa.text("ALTER TABLE organization_memberships DISABLE ROW LEVEL SECURITY;"))

    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_append_security_event("
            "varchar, varchar, integer, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_append_audit_event("
            "varchar, varchar, varchar, integer, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(sa.text("DROP FUNCTION IF EXISTS public.jyxia_get_security_audit_head();"))


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    with op.batch_alter_table("organization_memberships", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_organization_memberships_role_valid", type_="check")
        batch_op.create_check_constraint(
            "ck_organization_memberships_role_valid",
            "role IN ('org_admin', 'clinical_reviewer', 'admin_operator', 'auditor_readonly', 'read_only')",
        )
        batch_op.drop_constraint("ck_organization_memberships_status_valid", type_="check")
        batch_op.create_check_constraint(
            "ck_organization_memberships_status_valid",
            "status IN ('active', 'suspended', 'revoked')",
        )

    op.create_table(
        "external_identities",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("issuer", sa.String(length=255), nullable=False),
        sa.Column("subject", sa.String(length=255), nullable=False),
        sa.Column("email_at_binding", sa.String(length=255), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("last_authenticated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(trim(issuer)) >= 8",
            name="ck_external_identities_issuer_min_len",
        ),
        sa.CheckConstraint(
            "length(trim(subject)) >= 1",
            name="ck_external_identities_subject_nonempty",
        ),
        sa.CheckConstraint(
            "email_at_binding IS NULL OR email_at_binding = lower(email_at_binding)",
            name="ck_external_identities_email_lowercase",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'revoked')",
            name="ck_external_identities_status_valid",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_external_identities_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_external_identities"),
        sa.UniqueConstraint("issuer", "subject", name="uq_external_identities_iss_sub"),
    )
    op.create_index(
        "ix_external_identities_user",
        "external_identities",
        ["user_id"],
        unique=False,
    )

    op.create_table(
        "oidc_auth_states",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("code_verifier_ciphertext", sa.Text(), nullable=False),
        sa.Column("issuer", sa.String(length=255), nullable=False),
        sa.Column("redirect_uri", sa.String(length=500), nullable=False),
        sa.Column("next_path", sa.String(length=500), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(trim(state_hash)) = 64 AND state_hash = lower(state_hash)",
            name="ck_oidc_auth_states_state_hash_hex64",
        ),
        sa.CheckConstraint(
            "length(trim(nonce_hash)) = 64 AND nonce_hash = lower(nonce_hash)",
            name="ck_oidc_auth_states_nonce_hash_hex64",
        ),
        sa.CheckConstraint(
            "length(trim(code_verifier_ciphertext)) >= 16",
            name="ck_oidc_auth_states_verifier_cipher",
        ),
        sa.CheckConstraint(
            "length(trim(issuer)) >= 8",
            name="ck_oidc_auth_states_issuer_min_len",
        ),
        sa.CheckConstraint(
            "length(trim(redirect_uri)) >= 8",
            name="ck_oidc_auth_states_redirect_uri_min_len",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_oidc_auth_states"),
        sa.UniqueConstraint("state_hash", name="uq_oidc_auth_states_state_hash"),
    )
    op.create_index(
        "ix_oidc_auth_states_expires",
        "oidc_auth_states",
        ["expires_at"],
        unique=False,
    )

    op.create_table(
        "auth_sessions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("external_identity_id", sa.String(length=36), nullable=False),
        sa.Column("active_organization_id", sa.String(length=36), nullable=True),
        sa.Column("session_token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_token_hash", sa.String(length=64), nullable=False),
        sa.Column("auth_method", sa.String(length=64), nullable=False),
        sa.Column("acr", sa.String(length=255), nullable=False),
        sa.Column("amr_json", _JSON_VARIANT, nullable=False),
        sa.Column("mfa_verified_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("oidc_auth_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revocation_reason", sa.String(length=120), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "length(trim(session_token_hash)) = 64 AND session_token_hash = lower(session_token_hash)",
            name="ck_auth_sessions_session_hash_hex64",
        ),
        sa.CheckConstraint(
            "length(trim(csrf_token_hash)) = 64 AND csrf_token_hash = lower(csrf_token_hash)",
            name="ck_auth_sessions_csrf_hash_hex64",
        ),
        sa.CheckConstraint(
            "length(trim(auth_method)) >= 3",
            name="ck_auth_sessions_auth_method_min_len",
        ),
        sa.CheckConstraint(
            "length(trim(acr)) >= 1",
            name="ck_auth_sessions_acr_nonempty",
        ),
        sa.CheckConstraint(
            "absolute_expires_at >= created_at",
            name="ck_auth_sessions_abs_exp_after_created",
        ),
        sa.CheckConstraint(
            "idle_expires_at >= created_at",
            name="ck_auth_sessions_idle_exp_after_created",
        ),
        sa.ForeignKeyConstraint(
            ["active_organization_id"],
            ["organizations.id"],
            name="fk_auth_sessions_active_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["external_identity_id"],
            ["external_identities.id"],
            name="fk_auth_sessions_external_identity_id_external_identities",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_auth_sessions_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_auth_sessions"),
        sa.UniqueConstraint("session_token_hash", name="uq_auth_sessions_token_hash"),
    )
    op.create_index("ix_auth_sessions_user", "auth_sessions", ["user_id"], unique=False)
    op.create_index(
        "ix_auth_sessions_abs_exp",
        "auth_sessions",
        ["absolute_expires_at"],
        unique=False,
    )

    op.create_table(
        "security_auth_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column(
            "schema_version",
            sa.String(length=32),
            nullable=False,
            server_default=sa.text(f"'{SECURITY_AUDIT_SCHEMA_VERSION}'"),
        ),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("organization_id", sa.String(length=36), nullable=True),
        sa.Column("issuer", sa.String(length=255), nullable=True),
        sa.Column("subject_hash", sa.String(length=64), nullable=True),
        sa.Column("session_id", sa.String(length=36), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("reason_code", sa.String(length=80), nullable=False),
        sa.Column("payload_json", _JSON_VARIANT, nullable=False),
        sa.Column("prev_event_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "sequence_number >= 1",
            name="ck_security_auth_events_sequence_number_positive",
        ),
        sa.CheckConstraint(
            "length(trim(prev_event_hash)) = 64 AND prev_event_hash = lower(prev_event_hash)",
            name="ck_security_auth_events_prev_hash_len_64",
        ),
        sa.CheckConstraint(
            "length(trim(event_hash)) = 64 AND event_hash = lower(event_hash)",
            name="ck_security_auth_events_event_hash_len_64",
        ),
        sa.CheckConstraint(
            "length(trim(schema_version)) >= 3",
            name="ck_security_auth_events_schema_version_nonempty",
        ),
        sa.CheckConstraint(
            "length(trim(event_type)) >= 2",
            name="ck_security_auth_events_event_type_min_len",
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'denied', 'failure')",
            name="ck_security_auth_events_outcome_valid",
        ),
        sa.CheckConstraint(
            "length(trim(reason_code)) >= 2",
            name="ck_security_auth_events_reason_code_min_len",
        ),
        sa.CheckConstraint(
            "subject_hash IS NULL OR (length(trim(subject_hash)) = 64 AND subject_hash = lower(subject_hash))",
            name="ck_security_auth_events_subject_hash_hex64",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_security_auth_events_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_security_auth_events_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_security_auth_events"),
        sa.UniqueConstraint("sequence_number", name="uq_security_auth_events_seq"),
        sa.UniqueConstraint("event_hash", name="uq_security_auth_events_hash"),
    )
    op.create_index(
        "ix_security_auth_events_created",
        "security_auth_events",
        ["created_at"],
        unique=False,
    )
    op.create_index(
        "ix_security_auth_events_org_created",
        "security_auth_events",
        ["organization_id", "created_at"],
        unique=False,
    )

    _install_security_audit_and_truncate_triggers(dialect_name)
    if dialect_name == "postgresql":
        _install_pg_security_functions_rls_and_grants()


def downgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    if dialect_name == "postgresql":
        _drop_pg_security_functions_rls_and_grants()
    _drop_security_audit_and_truncate_triggers(dialect_name)

    op.drop_index("ix_security_auth_events_org_created", table_name="security_auth_events")
    op.drop_index("ix_security_auth_events_created", table_name="security_auth_events")
    op.drop_table("security_auth_events")

    op.drop_index("ix_auth_sessions_abs_exp", table_name="auth_sessions")
    op.drop_index("ix_auth_sessions_user", table_name="auth_sessions")
    op.drop_table("auth_sessions")

    op.drop_index("ix_oidc_auth_states_expires", table_name="oidc_auth_states")
    op.drop_table("oidc_auth_states")

    op.drop_index("ix_external_identities_user", table_name="external_identities")
    op.drop_table("external_identities")

    with op.batch_alter_table("organization_memberships", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_organization_memberships_status_valid", type_="check")
        batch_op.create_check_constraint(
            "ck_organization_memberships_status_valid",
            "status IN ('active', 'revoked')",
        )
        batch_op.drop_constraint("ck_organization_memberships_role_valid", type_="check")
        batch_op.create_check_constraint(
            "ck_organization_memberships_role_valid",
            "role IN ('org_admin', 'clinical_reviewer', 'admin_operator', 'auditor_readonly')",
        )
