"""Harden human_reviews append-only immutability, review uniqueness, and concurrent comparison queueing.

Revision ID: 20261125_0010
Revises: 20261122_0009
Create Date: 2026-11-25 18:35:00.000000+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa

revision: str = "20261125_0010"
down_revision: str | None = "20261122_0009"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def _upgrade_pg_human_reviews_and_worker_claim() -> None:
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_forbid_human_review_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                RAISE EXCEPTION 'human_reviews table is strictly append-only; % is forbidden', TG_OP;
            END;
            $$;
            """
        )
    )
    op.execute(sa.text("DROP TRIGGER IF EXISTS trg_human_reviews_append_only ON public.human_reviews;"))
    op.execute(
        sa.text(
            """
            CREATE TRIGGER trg_human_reviews_append_only
            BEFORE UPDATE OR DELETE ON public.human_reviews
            FOR EACH ROW
            EXECUTE FUNCTION public.jyxia_forbid_human_review_mutation();
            """
        )
    )
    op.execute(sa.text("DROP TRIGGER IF EXISTS trg_human_reviews_no_truncate ON public.human_reviews;"))
    op.execute(
        sa.text(
            """
            CREATE TRIGGER trg_human_reviews_no_truncate
            BEFORE TRUNCATE ON public.human_reviews
            FOR EACH STATEMENT
            EXECUTE FUNCTION public.jyxia_forbid_human_review_mutation();
            """
        )
    )

    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                REVOKE ALL ON TABLE public.human_reviews FROM PUBLIC;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    REVOKE UPDATE, DELETE, TRUNCATE ON TABLE public.human_reviews FROM jyxia_app;
                    GRANT SELECT, INSERT ON TABLE public.human_reviews TO jyxia_app;
                END IF;
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_worker') THEN
                    REVOKE ALL ON TABLE public.human_reviews FROM jyxia_worker;
                END IF;
            END
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_claim_next_run(
                p_worker_id varchar,
                p_lease_token_hash varchar,
                p_lease_seconds integer,
                p_step_type varchar
            )
            RETURNS TABLE (
                run_id varchar,
                organization_id varchar,
                document_version_id varchar,
                document_id varchar,
                case_id varchar,
                step_type varchar,
                policy_version varchar,
                extractor_version varchar,
                idempotency_key varchar,
                triggered_by_user_id varchar,
                attempt_count integer,
                max_attempts integer,
                started_at timestamptz,
                available_at timestamptz,
                lease_expires_at timestamptz,
                sha256_hex varchar,
                mime_type varchar,
                byte_size bigint,
                page_count integer,
                storage_driver varchar,
                storage_key varchar,
                last_audit_sequence integer,
                last_audit_event_hash varchar
            )
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            #variable_conflict use_column
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_doc_id varchar;
                v_case_id varchar;
                v_sha256 varchar;
                v_mime varchar;
                v_byte_size bigint;
                v_page_count integer;
                v_storage_driver varchar;
                v_storage_key varchar;
                v_org_locked varchar;
                v_last_seq integer;
                v_last_hash varchar;
                v_requested_step varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker claim rejected for session_user %', session_user;
                END IF;

                IF p_worker_id IS NULL OR length(trim(p_worker_id)) < 3 THEN
                    RAISE EXCEPTION 'Worker claim rejected: invalid worker_id';
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker claim rejected: invalid lease_token_hash';
                END IF;

                IF p_lease_seconds IS NULL OR p_lease_seconds < 1 OR p_lease_seconds > 86400 THEN
                    RAISE EXCEPTION 'Worker claim rejected: invalid lease_seconds';
                END IF;

                v_requested_step := COALESCE(NULLIF(trim(p_step_type), ''), 'any');
                IF v_requested_step NOT IN (
                    'any',
                    'verify_object_integrity',
                    'extract_pdf_text',
                    'compare_consistency'
                ) THEN
                    RAISE EXCEPTION 'Worker claim rejected: unsupported step_type %', v_requested_step;
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                JOIN public.organizations AS o ON o.id = pr.organization_id
                WHERE pr.status IN ('queued', 'retry_wait')
                  AND (
                        (
                            v_requested_step = 'any'
                            AND pr.step_type IN (
                                'verify_object_integrity',
                                'extract_pdf_text',
                                'compare_consistency'
                            )
                        )
                        OR pr.step_type = v_requested_step
                  )
                  AND (
                        pr.step_type <> 'extract_pdf_text'
                        OR EXISTS (
                            SELECT 1
                            FROM public.processing_runs AS vr
                            WHERE vr.organization_id = pr.organization_id
                              AND vr.document_version_id = pr.document_version_id
                              AND vr.step_type = 'verify_object_integrity'
                              AND vr.status = 'succeeded'
                        )
                  )
                  AND (
                        pr.step_type <> 'compare_consistency'
                        OR pr.case_id IS NULL
                        OR NOT EXISTS (
                            SELECT 1
                            FROM public.processing_runs AS cr
                            WHERE cr.organization_id = pr.organization_id
                              AND cr.case_id = pr.case_id
                              AND cr.step_type = 'compare_consistency'
                              AND cr.status = 'running'
                        )
                  )
                  AND pr.available_at <= v_now
                  AND pr.attempt_count < pr.max_attempts
                  AND o.status = 'active'
                ORDER BY pr.available_at ASC, pr.created_at ASC
                FOR UPDATE OF pr SKIP LOCKED
                LIMIT 1;

                IF v_run.id IS NULL THEN
                    RETURN;
                END IF;

                UPDATE public.processing_runs AS pr
                SET status = 'running',
                    attempt_count = v_run.attempt_count + 1,
                    started_at = COALESCE(v_run.started_at, v_now),
                    worker_id = p_worker_id,
                    lease_token_hash = p_lease_token_hash,
                    lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds::double precision),
                    updated_at = GREATEST(v_now, v_run.created_at)
                WHERE pr.id = v_run.id
                RETURNING pr.* INTO v_run;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                SELECT
                    dv.document_id::varchar,
                    COALESCE(v_run.case_id, d.case_id)::varchar,
                    dv.sha256_hex::varchar,
                    dv.mime_type::varchar,
                    dv.byte_size::bigint,
                    dv.page_count::integer,
                    dv.storage_driver::varchar,
                    dv.storage_key::varchar
                INTO
                    v_doc_id,
                    v_case_id,
                    v_sha256,
                    v_mime,
                    v_byte_size,
                    v_page_count,
                    v_storage_driver,
                    v_storage_key
                FROM public.document_versions AS dv
                JOIN public.documents AS d
                  ON d.organization_id = dv.organization_id
                 AND d.id = dv.document_id
                WHERE dv.organization_id = v_run.organization_id
                  AND dv.id = v_run.document_version_id;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                SELECT COALESCE(MAX(ae.sequence_number), 0) INTO v_last_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = v_run.organization_id;

                IF v_last_seq = 0 THEN
                    v_last_hash := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_last_hash
                    FROM public.audit_events AS ae
                    WHERE ae.organization_id = v_run.organization_id
                      AND ae.sequence_number = v_last_seq;
                END IF;

                PERFORM pg_catalog.set_config('app.current_organization_id', '', true);

                RETURN QUERY SELECT
                    v_run.id::varchar,
                    v_run.organization_id::varchar,
                    v_run.document_version_id::varchar,
                    v_doc_id::varchar,
                    v_case_id::varchar,
                    v_run.step_type::varchar,
                    v_run.policy_version::varchar,
                    v_run.extractor_version::varchar,
                    v_run.idempotency_key::varchar,
                    v_run.triggered_by_user_id::varchar,
                    v_run.attempt_count::integer,
                    v_run.max_attempts::integer,
                    v_run.started_at::timestamptz,
                    v_run.available_at::timestamptz,
                    v_run.lease_expires_at::timestamptz,
                    v_sha256::varchar,
                    v_mime::varchar,
                    v_byte_size::bigint,
                    v_page_count::integer,
                    v_storage_driver::varchar,
                    v_storage_key::varchar,
                    v_last_seq::integer,
                    v_last_hash::varchar;
            END;
            $$;
            """
        )
    )


def _downgrade_pg_human_reviews_and_worker_claim() -> None:
    op.execute(sa.text("DROP TRIGGER IF EXISTS trg_human_reviews_no_truncate ON public.human_reviews;"))
    op.execute(sa.text("DROP TRIGGER IF EXISTS trg_human_reviews_append_only ON public.human_reviews;"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS public.jyxia_forbid_human_review_mutation();"))

    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.human_reviews TO jyxia_app;
                END IF;
            END
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_claim_next_run(
                p_worker_id varchar,
                p_lease_token_hash varchar,
                p_lease_seconds integer,
                p_step_type varchar
            )
            RETURNS TABLE (
                run_id varchar,
                organization_id varchar,
                document_version_id varchar,
                document_id varchar,
                case_id varchar,
                step_type varchar,
                policy_version varchar,
                extractor_version varchar,
                idempotency_key varchar,
                triggered_by_user_id varchar,
                attempt_count integer,
                max_attempts integer,
                started_at timestamptz,
                available_at timestamptz,
                lease_expires_at timestamptz,
                sha256_hex varchar,
                mime_type varchar,
                byte_size bigint,
                page_count integer,
                storage_driver varchar,
                storage_key varchar,
                last_audit_sequence integer,
                last_audit_event_hash varchar
            )
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            #variable_conflict use_column
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_doc_id varchar;
                v_case_id varchar;
                v_sha256 varchar;
                v_mime varchar;
                v_byte_size bigint;
                v_page_count integer;
                v_storage_driver varchar;
                v_storage_key varchar;
                v_org_locked varchar;
                v_last_seq integer;
                v_last_hash varchar;
                v_requested_step varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker claim rejected for session_user %', session_user;
                END IF;

                IF p_worker_id IS NULL OR length(trim(p_worker_id)) < 3 THEN
                    RAISE EXCEPTION 'Worker claim rejected: invalid worker_id';
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker claim rejected: invalid lease_token_hash';
                END IF;

                IF p_lease_seconds IS NULL OR p_lease_seconds < 1 OR p_lease_seconds > 86400 THEN
                    RAISE EXCEPTION 'Worker claim rejected: invalid lease_seconds';
                END IF;

                v_requested_step := COALESCE(NULLIF(trim(p_step_type), ''), 'any');
                IF v_requested_step NOT IN (
                    'any',
                    'verify_object_integrity',
                    'extract_pdf_text',
                    'compare_consistency'
                ) THEN
                    RAISE EXCEPTION 'Worker claim rejected: unsupported step_type %', v_requested_step;
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                JOIN public.organizations AS o ON o.id = pr.organization_id
                WHERE pr.status IN ('queued', 'retry_wait')
                  AND (
                        (
                            v_requested_step = 'any'
                            AND pr.step_type IN (
                                'verify_object_integrity',
                                'extract_pdf_text',
                                'compare_consistency'
                            )
                        )
                        OR pr.step_type = v_requested_step
                  )
                  AND (
                        pr.step_type <> 'extract_pdf_text'
                        OR EXISTS (
                            SELECT 1
                            FROM public.processing_runs AS vr
                            WHERE vr.organization_id = pr.organization_id
                              AND vr.document_version_id = pr.document_version_id
                              AND vr.step_type = 'verify_object_integrity'
                              AND vr.status = 'succeeded'
                        )
                  )
                  AND pr.available_at <= v_now
                  AND pr.attempt_count < pr.max_attempts
                  AND o.status = 'active'
                ORDER BY pr.available_at ASC, pr.created_at ASC
                FOR UPDATE OF pr SKIP LOCKED
                LIMIT 1;

                IF v_run.id IS NULL THEN
                    RETURN;
                END IF;

                UPDATE public.processing_runs AS pr
                SET status = 'running',
                    attempt_count = v_run.attempt_count + 1,
                    started_at = COALESCE(v_run.started_at, v_now),
                    worker_id = p_worker_id,
                    lease_token_hash = p_lease_token_hash,
                    lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds::double precision),
                    updated_at = GREATEST(v_now, v_run.created_at)
                WHERE pr.id = v_run.id
                RETURNING pr.* INTO v_run;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                SELECT
                    dv.document_id::varchar,
                    COALESCE(v_run.case_id, d.case_id)::varchar,
                    dv.sha256_hex::varchar,
                    dv.mime_type::varchar,
                    dv.byte_size::bigint,
                    dv.page_count::integer,
                    dv.storage_driver::varchar,
                    dv.storage_key::varchar
                INTO
                    v_doc_id,
                    v_case_id,
                    v_sha256,
                    v_mime,
                    v_byte_size,
                    v_page_count,
                    v_storage_driver,
                    v_storage_key
                FROM public.document_versions AS dv
                JOIN public.documents AS d
                  ON d.organization_id = dv.organization_id
                 AND d.id = dv.document_id
                WHERE dv.organization_id = v_run.organization_id
                  AND dv.id = v_run.document_version_id;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                SELECT COALESCE(MAX(ae.sequence_number), 0) INTO v_last_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = v_run.organization_id;

                IF v_last_seq = 0 THEN
                    v_last_hash := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_last_hash
                    FROM public.audit_events AS ae
                    WHERE ae.organization_id = v_run.organization_id
                      AND ae.sequence_number = v_last_seq;
                END IF;

                PERFORM pg_catalog.set_config('app.current_organization_id', '', true);

                RETURN QUERY SELECT
                    v_run.id::varchar,
                    v_run.organization_id::varchar,
                    v_run.document_version_id::varchar,
                    v_doc_id::varchar,
                    v_case_id::varchar,
                    v_run.step_type::varchar,
                    v_run.policy_version::varchar,
                    v_run.extractor_version::varchar,
                    v_run.idempotency_key::varchar,
                    v_run.triggered_by_user_id::varchar,
                    v_run.attempt_count::integer,
                    v_run.max_attempts::integer,
                    v_run.started_at::timestamptz,
                    v_run.available_at::timestamptz,
                    v_run.lease_expires_at::timestamptz,
                    v_sha256::varchar,
                    v_mime::varchar,
                    v_byte_size::bigint,
                    v_page_count::integer,
                    v_storage_driver::varchar,
                    v_storage_key::varchar,
                    v_last_seq::integer,
                    v_last_hash::varchar;
            END;
            $$;
            """
        )
    )


def upgrade() -> None:
    bind = op.get_bind()

    op.create_index(
        "uq_human_reviews_general_ver_action",
        "human_reviews",
        ["organization_id", "document_version_id", "action_type"],
        unique=True,
        sqlite_where=sa.text("field_key IS NULL"),
        postgresql_where=sa.text("field_key IS NULL"),
    )
    op.create_index(
        "uq_human_reviews_field_ver_action",
        "human_reviews",
        ["organization_id", "document_version_id", "action_type", "field_key"],
        unique=True,
        sqlite_where=sa.text("field_key IS NOT NULL"),
        postgresql_where=sa.text("field_key IS NOT NULL"),
    )

    op.drop_index("uq_processing_runs_active_ver_step", table_name="processing_runs")
    op.create_index(
        "uq_processing_runs_active_ver_step",
        "processing_runs",
        ["organization_id", "document_version_id", "step_type"],
        unique=True,
        sqlite_where=sa.text(
            "step_type <> 'compare_consistency' "
            "AND status IN ('queued', 'running', 'retry_wait')"
        ),
        postgresql_where=sa.text(
            "step_type <> 'compare_consistency' "
            "AND status IN ('queued', 'running', 'retry_wait')"
        ),
    )

    op.drop_index("uq_processing_runs_active_case_compare", table_name="processing_runs")
    op.create_index(
        "uq_processing_runs_active_case_compare",
        "processing_runs",
        ["organization_id", "case_id"],
        unique=True,
        sqlite_where=sa.text(
            "step_type = 'compare_consistency' "
            "AND status IN ('queued', 'retry_wait') "
            "AND case_id IS NOT NULL"
        ),
        postgresql_where=sa.text(
            "step_type = 'compare_consistency' "
            "AND status IN ('queued', 'retry_wait') "
            "AND case_id IS NOT NULL"
        ),
    )

    if bind.dialect.name == "postgresql":
        _upgrade_pg_human_reviews_and_worker_claim()
    elif bind.dialect.name == "sqlite":
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_human_reviews_no_update;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_human_reviews_no_delete;"))
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_human_reviews_no_update
                BEFORE UPDATE ON human_reviews
                BEGIN
                    SELECT RAISE(ABORT, 'human_reviews table is strictly append-only; UPDATE is forbidden');
                END;
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_human_reviews_no_delete
                BEFORE DELETE ON human_reviews
                BEGIN
                    SELECT RAISE(ABORT, 'human_reviews table is strictly append-only; DELETE is forbidden');
                END;
                """
            )
        )


def downgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name == "postgresql":
        _downgrade_pg_human_reviews_and_worker_claim()
    elif bind.dialect.name == "sqlite":
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_human_reviews_no_delete;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_human_reviews_no_update;"))

    op.drop_index("uq_processing_runs_active_ver_step", table_name="processing_runs")
    op.create_index(
        "uq_processing_runs_active_ver_step",
        "processing_runs",
        ["organization_id", "document_version_id", "step_type"],
        unique=True,
        sqlite_where=sa.text(
            "step_type <> 'compare_consistency' "
            "AND status IN ('queued', 'running', 'retry_wait')"
        ),
        postgresql_where=sa.text(
            "step_type <> 'compare_consistency' "
            "AND status IN ('queued', 'running', 'retry_wait')"
        ),
    )

    op.drop_index("uq_processing_runs_active_case_compare", table_name="processing_runs")
    op.create_index(
        "uq_processing_runs_active_case_compare",
        "processing_runs",
        ["organization_id", "case_id"],
        unique=True,
        sqlite_where=sa.text(
            "step_type = 'compare_consistency' "
            "AND status IN ('queued', 'running', 'retry_wait') "
            "AND case_id IS NOT NULL"
        ),
        postgresql_where=sa.text(
            "step_type = 'compare_consistency' "
            "AND status IN ('queued', 'running', 'retry_wait') "
            "AND case_id IS NOT NULL"
        ),
    )

    op.drop_index("uq_processing_runs_active_ver_step", table_name="processing_runs")
    op.create_index(
        "uq_processing_runs_active_ver_step",
        "processing_runs",
        ["organization_id", "document_version_id", "step_type"],
        unique=True,
        sqlite_where=sa.text("status IN ('queued', 'running', 'retry_wait')"),
        postgresql_where=sa.text("status IN ('queued', 'running', 'retry_wait')"),
    )

    op.drop_index("uq_human_reviews_field_ver_action", table_name="human_reviews")
    op.drop_index("uq_human_reviews_general_ver_action", table_name="human_reviews")
