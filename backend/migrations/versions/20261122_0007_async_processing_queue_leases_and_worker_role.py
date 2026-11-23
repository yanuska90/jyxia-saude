"""Add durable async processing queue columns, lease fencing, partial uniqueness, and jyxia_worker role.

Revision ID: 20261122_0007
Revises: 20261122_0006
Create Date: 2026-11-23 10:00:00+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "20261122_0007"
down_revision = "20261122_0006"
branch_labels = None
depends_on = None

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

_JSON_VARIANT = sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")

_NEW_STATUS_SQL = (
    "status IN ('queued', 'pending', 'running', 'retry_wait', 'succeeded', "
    "'completed', 'abstained', 'quarantined', 'failed', 'cancelled')"
)
_OLD_STATUS_SQL = "status IN ('pending', 'running', 'completed', 'abstained', 'quarantined', 'failed')"
_STEP_TYPE_SQL = "step_type IN ('verify_object_integrity')"
_ACTIVE_WHERE_SQL = "status IN ('queued', 'running', 'retry_wait')"


def _upgrade_pg_worker_functions_rls_and_grants() -> None:
    op.execute(
        sa.text(
            """
            CREATE POLICY p_processing_runs_worker_queue_definer ON public.processing_runs
            FOR ALL
            USING (
                session_user = 'jyxia_worker'
                AND pg_catalog.current_user <> pg_catalog.session_user
            )
            WITH CHECK (
                session_user = 'jyxia_worker'
                AND pg_catalog.current_user <> pg_catalog.session_user
            );
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

                IF p_step_type IS NULL OR p_step_type <> 'verify_object_integrity' THEN
                    RAISE EXCEPTION 'Worker claim rejected: unsupported step_type';
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                JOIN public.organizations AS o ON o.id = pr.organization_id
                WHERE pr.status IN ('queued', 'retry_wait')
                  AND pr.step_type = p_step_type
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
                    lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds),
                    updated_at = GREATEST(v_now, v_run.created_at)
                WHERE pr.id = v_run.id
                RETURNING pr.* INTO v_run;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                SELECT
                    dv.document_id::varchar,
                    d.case_id::varchar,
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

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_prepare_run_audit_head(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar
            )
            RETURNS TABLE (
                organization_id varchar,
                last_sequence integer,
                last_event_hash varchar
            )
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_org_locked varchar;
                v_last_seq integer;
                v_last_hash varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker audit preparation rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker audit preparation rejected: invalid lease_token_hash';
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                WHERE pr.id = p_run_id
                FOR UPDATE;

                IF v_run.id IS NULL THEN
                    RAISE EXCEPTION 'Worker audit preparation rejected: unknown processing_run %', p_run_id;
                END IF;

                IF v_run.status <> 'running'
                   OR v_run.worker_id IS DISTINCT FROM p_worker_id
                   OR v_run.lease_token_hash IS DISTINCT FROM p_lease_token_hash
                   OR v_run.lease_expires_at IS NULL
                   OR v_run.lease_expires_at < v_now THEN
                    RAISE EXCEPTION 'Worker lease invalid or expired for processing_run %', p_run_id;
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

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
                    v_run.organization_id::varchar,
                    v_last_seq::integer,
                    v_last_hash::varchar;
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_append_started_audit(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar,
                p_audit_id varchar,
                p_audit_sequence_number integer,
                p_audit_payload_json text,
                p_audit_prev_event_hash varchar,
                p_audit_event_hash varchar,
                p_audit_created_at timestamptz
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_org_locked varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker audit append rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker audit append rejected: invalid lease_token_hash';
                END IF;

                IF p_audit_prev_event_hash IS NULL OR p_audit_prev_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker audit append rejected: invalid prev_event_hash';
                END IF;

                IF p_audit_event_hash IS NULL OR p_audit_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker audit append rejected: invalid event_hash';
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                WHERE pr.id = p_run_id
                FOR UPDATE;

                IF v_run.id IS NULL
                   OR v_run.status <> 'running'
                   OR v_run.worker_id IS DISTINCT FROM p_worker_id
                   OR v_run.lease_token_hash IS DISTINCT FROM p_lease_token_hash
                   OR v_run.lease_expires_at IS NULL
                   OR v_run.lease_expires_at < v_now THEN
                    RAISE EXCEPTION 'Worker lease invalid or expired for started audit on %', p_run_id;
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                SELECT COALESCE(MAX(ae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = v_run.organization_id;

                IF p_audit_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Worker audit sequence mismatch: expected %, got %', v_expected_seq, p_audit_sequence_number;
                END IF;

                IF v_expected_seq = 1 THEN
                    v_expected_prev := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_expected_prev
                    FROM public.audit_events AS ae
                    WHERE ae.organization_id = v_run.organization_id
                      AND ae.sequence_number = v_expected_seq - 1;
                END IF;

                IF p_audit_prev_event_hash <> v_expected_prev THEN
                    RAISE EXCEPTION 'Worker audit prev_event_hash mismatch for sequence %', p_audit_sequence_number;
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
                    p_audit_id,
                    v_run.organization_id,
                    'jyxia.audit.v1',
                    p_audit_sequence_number,
                    NULL,
                    'processing_run.started',
                    'processing_run',
                    v_run.id,
                    p_audit_payload_json::jsonb,
                    p_audit_prev_event_hash,
                    p_audit_event_hash,
                    p_audit_created_at
                );

                PERFORM pg_catalog.set_config('app.current_organization_id', '', true);
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_complete_run(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar,
                p_result_json text,
                p_audit_id varchar,
                p_audit_sequence_number integer,
                p_audit_payload_json text,
                p_audit_prev_event_hash varchar,
                p_audit_event_hash varchar,
                p_audit_created_at timestamptz
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_org_locked varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker complete rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker complete rejected: invalid lease_token_hash';
                END IF;

                IF p_audit_prev_event_hash IS NULL OR p_audit_prev_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker complete rejected: invalid prev_event_hash';
                END IF;

                IF p_audit_event_hash IS NULL OR p_audit_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker complete rejected: invalid event_hash';
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                WHERE pr.id = p_run_id
                FOR UPDATE;

                IF v_run.id IS NULL
                   OR v_run.status <> 'running'
                   OR v_run.worker_id IS DISTINCT FROM p_worker_id
                   OR v_run.lease_token_hash IS DISTINCT FROM p_lease_token_hash
                   OR v_run.lease_expires_at IS NULL
                   OR v_run.lease_expires_at < v_now THEN
                    RAISE EXCEPTION 'Worker lease invalid or expired for completion of %', p_run_id;
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                UPDATE public.processing_runs AS pr
                SET status = 'succeeded',
                    lease_expires_at = NULL,
                    lease_token_hash = NULL,
                    last_error_code = NULL,
                    last_error_detail = NULL,
                    result_json = CASE WHEN p_result_json IS NULL THEN NULL ELSE p_result_json::jsonb END,
                    readable = FALSE,
                    readiness_state = NULL,
                    finished_at = GREATEST(v_now, COALESCE(v_run.started_at, v_now)),
                    updated_at = GREATEST(v_now, v_run.created_at)
                WHERE pr.id = v_run.id;

                SELECT COALESCE(MAX(ae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = v_run.organization_id;

                IF p_audit_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Worker completion audit sequence mismatch: expected %, got %', v_expected_seq, p_audit_sequence_number;
                END IF;

                IF v_expected_seq = 1 THEN
                    v_expected_prev := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_expected_prev
                    FROM public.audit_events AS ae
                    WHERE ae.organization_id = v_run.organization_id
                      AND ae.sequence_number = v_expected_seq - 1;
                END IF;

                IF p_audit_prev_event_hash <> v_expected_prev THEN
                    RAISE EXCEPTION 'Worker completion audit prev_event_hash mismatch for sequence %', p_audit_sequence_number;
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
                    p_audit_id,
                    v_run.organization_id,
                    'jyxia.audit.v1',
                    p_audit_sequence_number,
                    NULL,
                    'processing_run.succeeded',
                    'processing_run',
                    v_run.id,
                    p_audit_payload_json::jsonb,
                    p_audit_prev_event_hash,
                    p_audit_event_hash,
                    p_audit_created_at
                );

                PERFORM pg_catalog.set_config('app.current_organization_id', '', true);
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_fail_or_retry_run(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar,
                p_target_status varchar,
                p_available_at timestamptz,
                p_error_code varchar,
                p_error_detail varchar,
                p_result_json text,
                p_audit_id varchar,
                p_audit_sequence_number integer,
                p_audit_event_type varchar,
                p_audit_payload_json text,
                p_audit_prev_event_hash varchar,
                p_audit_event_hash varchar,
                p_audit_created_at timestamptz
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_org_locked varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker failure update rejected for session_user %', session_user;
                END IF;

                IF p_target_status NOT IN ('retry_wait', 'failed') THEN
                    RAISE EXCEPTION 'Invalid target failure status %', COALESCE(p_target_status, '<null>');
                END IF;

                IF (p_target_status = 'retry_wait' AND p_audit_event_type <> 'processing_run.retry_scheduled')
                   OR (p_target_status = 'failed' AND p_audit_event_type <> 'processing_run.failed') THEN
                    RAISE EXCEPTION 'Audit event_type % mismatches target status %', p_audit_event_type, p_target_status;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker fail/retry rejected: invalid lease_token_hash';
                END IF;

                IF p_error_code IS NULL OR length(trim(p_error_code)) < 2 THEN
                    RAISE EXCEPTION 'Worker fail/retry rejected: invalid error_code';
                END IF;

                IF p_audit_prev_event_hash IS NULL OR p_audit_prev_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker fail/retry rejected: invalid prev_event_hash';
                END IF;

                IF p_audit_event_hash IS NULL OR p_audit_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker fail/retry rejected: invalid event_hash';
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                WHERE pr.id = p_run_id
                FOR UPDATE;

                IF v_run.id IS NULL
                   OR v_run.status <> 'running'
                   OR v_run.worker_id IS DISTINCT FROM p_worker_id
                   OR v_run.lease_token_hash IS DISTINCT FROM p_lease_token_hash
                   OR v_run.lease_expires_at IS NULL
                   OR v_run.lease_expires_at < v_now THEN
                    RAISE EXCEPTION 'Worker lease invalid or expired for failure update on %', p_run_id;
                END IF;

                IF p_target_status = 'retry_wait' AND v_run.attempt_count >= v_run.max_attempts THEN
                    RAISE EXCEPTION 'Cannot schedule retry_wait when attempt_count (%) >= max_attempts (%)',
                        v_run.attempt_count, v_run.max_attempts;
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                UPDATE public.processing_runs AS pr
                SET status = p_target_status,
                    available_at = COALESCE(p_available_at, v_now),
                    lease_expires_at = NULL,
                    lease_token_hash = NULL,
                    last_error_code = p_error_code,
                    last_error_detail = p_error_detail,
                    result_json = CASE WHEN p_result_json IS NULL THEN NULL ELSE p_result_json::jsonb END,
                    readable = FALSE,
                    readiness_state = NULL,
                    finished_at = CASE
                        WHEN p_target_status = 'failed' THEN GREATEST(v_now, COALESCE(v_run.started_at, v_now))
                        ELSE NULL
                    END,
                    updated_at = GREATEST(v_now, v_run.created_at)
                WHERE pr.id = v_run.id;

                SELECT COALESCE(MAX(ae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = v_run.organization_id;

                IF p_audit_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Worker fail/retry audit sequence mismatch: expected %, got %', v_expected_seq, p_audit_sequence_number;
                END IF;

                IF v_expected_seq = 1 THEN
                    v_expected_prev := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_expected_prev
                    FROM public.audit_events AS ae
                    WHERE ae.organization_id = v_run.organization_id
                      AND ae.sequence_number = v_expected_seq - 1;
                END IF;

                IF p_audit_prev_event_hash <> v_expected_prev THEN
                    RAISE EXCEPTION 'Worker fail/retry audit prev_event_hash mismatch for sequence %', p_audit_sequence_number;
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
                    p_audit_id,
                    v_run.organization_id,
                    'jyxia.audit.v1',
                    p_audit_sequence_number,
                    NULL,
                    p_audit_event_type,
                    'processing_run',
                    v_run.id,
                    p_audit_payload_json::jsonb,
                    p_audit_prev_event_hash,
                    p_audit_event_hash,
                    p_audit_created_at
                );

                PERFORM pg_catalog.set_config('app.current_organization_id', '', true);
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_begin_expired_reclaim()
            RETURNS TABLE (
                run_id varchar,
                organization_id varchar,
                document_version_id varchar,
                step_type varchar,
                attempt_count integer,
                max_attempts integer,
                previous_worker_id varchar,
                lease_expires_at timestamptz,
                last_audit_sequence integer,
                last_audit_event_hash varchar
            )
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_org_locked varchar;
                v_last_seq integer;
                v_last_hash varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker reclaim begin rejected for session_user %', session_user;
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                WHERE pr.status = 'running'
                  AND pr.lease_expires_at IS NOT NULL
                  AND pr.lease_expires_at < v_now
                ORDER BY pr.lease_expires_at ASC
                FOR UPDATE OF pr SKIP LOCKED
                LIMIT 1;

                IF v_run.id IS NULL THEN
                    RETURN;
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

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
                    v_run.step_type::varchar,
                    v_run.attempt_count::integer,
                    v_run.max_attempts::integer,
                    v_run.worker_id::varchar,
                    v_run.lease_expires_at::timestamptz,
                    v_last_seq::integer,
                    v_last_hash::varchar;
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_finish_expired_reclaim(
                p_run_id varchar,
                p_target_status varchar,
                p_available_at timestamptz,
                p_error_code varchar,
                p_error_detail varchar,
                p_audit_id varchar,
                p_audit_sequence_number integer,
                p_audit_event_type varchar,
                p_audit_payload_json text,
                p_audit_prev_event_hash varchar,
                p_audit_event_hash varchar,
                p_audit_created_at timestamptz
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_org_locked varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker reclaim finish rejected for session_user %', session_user;
                END IF;

                IF p_target_status NOT IN ('queued', 'retry_wait', 'failed') THEN
                    RAISE EXCEPTION 'Invalid reclaim target status %', COALESCE(p_target_status, '<null>');
                END IF;

                IF p_audit_event_type NOT IN ('processing_run.lease_reclaimed', 'processing_run.retry_scheduled', 'processing_run.failed') THEN
                    RAISE EXCEPTION 'Invalid reclaim audit event_type %', COALESCE(p_audit_event_type, '<null>');
                END IF;

                IF p_error_code IS NULL OR length(trim(p_error_code)) < 2 THEN
                    RAISE EXCEPTION 'Worker reclaim finish rejected: invalid error_code';
                END IF;

                IF p_audit_prev_event_hash IS NULL OR p_audit_prev_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker reclaim finish rejected: invalid prev_event_hash';
                END IF;

                IF p_audit_event_hash IS NULL OR p_audit_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker reclaim finish rejected: invalid event_hash';
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                WHERE pr.id = p_run_id
                FOR UPDATE;

                IF v_run.id IS NULL
                   OR v_run.status <> 'running'
                   OR v_run.lease_expires_at IS NULL
                   OR v_run.lease_expires_at >= v_now THEN
                    RAISE EXCEPTION 'Run % does not hold an expired running lease', p_run_id;
                END IF;

                IF v_run.attempt_count >= v_run.max_attempts AND p_target_status <> 'failed' THEN
                    RAISE EXCEPTION 'Expired run % reached max_attempts and must transition to failed', p_run_id;
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                UPDATE public.processing_runs AS pr
                SET status = p_target_status,
                    available_at = COALESCE(p_available_at, v_now),
                    lease_expires_at = NULL,
                    lease_token_hash = NULL,
                    worker_id = NULL,
                    last_error_code = p_error_code,
                    last_error_detail = p_error_detail,
                    finished_at = CASE
                        WHEN p_target_status = 'failed' THEN GREATEST(v_now, COALESCE(v_run.started_at, v_now))
                        ELSE NULL
                    END,
                    updated_at = GREATEST(v_now, v_run.created_at)
                WHERE pr.id = v_run.id;

                SELECT COALESCE(MAX(ae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = v_run.organization_id;

                IF p_audit_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Worker reclaim audit sequence mismatch: expected %, got %', v_expected_seq, p_audit_sequence_number;
                END IF;

                IF v_expected_seq = 1 THEN
                    v_expected_prev := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_expected_prev
                    FROM public.audit_events AS ae
                    WHERE ae.organization_id = v_run.organization_id
                      AND ae.sequence_number = v_expected_seq - 1;
                END IF;

                IF p_audit_prev_event_hash <> v_expected_prev THEN
                    RAISE EXCEPTION 'Worker reclaim audit prev_event_hash mismatch for sequence %', p_audit_sequence_number;
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
                    p_audit_id,
                    v_run.organization_id,
                    'jyxia.audit.v1',
                    p_audit_sequence_number,
                    NULL,
                    p_audit_event_type,
                    'processing_run',
                    v_run.id,
                    p_audit_payload_json::jsonb,
                    p_audit_prev_event_hash,
                    p_audit_event_hash,
                    p_audit_created_at
                );

                PERFORM pg_catalog.set_config('app.current_organization_id', '', true);
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
                REVOKE ALL ON FUNCTION public.jyxia_worker_claim_next_run(varchar, varchar, integer, varchar) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_prepare_run_audit_head(varchar, varchar, varchar) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_append_started_audit(varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_complete_run(varchar, varchar, varchar, text, varchar, integer, text, varchar, varchar, timestamptz) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_fail_or_retry_run(varchar, varchar, varchar, varchar, timestamptz, varchar, varchar, text, varchar, integer, varchar, text, varchar, varchar, timestamptz) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_begin_expired_reclaim() FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_finish_expired_reclaim(varchar, varchar, timestamptz, varchar, varchar, varchar, integer, varchar, text, varchar, varchar, timestamptz) FROM PUBLIC;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    REVOKE ALL ON FUNCTION public.jyxia_worker_claim_next_run(varchar, varchar, integer, varchar) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_prepare_run_audit_head(varchar, varchar, varchar) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_append_started_audit(varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_complete_run(varchar, varchar, varchar, text, varchar, integer, text, varchar, varchar, timestamptz) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_fail_or_retry_run(varchar, varchar, varchar, varchar, timestamptz, varchar, varchar, text, varchar, integer, varchar, text, varchar, varchar, timestamptz) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_begin_expired_reclaim() FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_finish_expired_reclaim(varchar, varchar, timestamptz, varchar, varchar, varchar, integer, varchar, text, varchar, varchar, timestamptz) FROM jyxia_app;
                END IF;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_worker') THEN
                    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC, jyxia_worker;
                    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, jyxia_worker;
                    REVOKE ALL ON SCHEMA public FROM jyxia_worker;
                    GRANT USAGE ON SCHEMA public TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_claim_next_run(varchar, varchar, integer, varchar) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_prepare_run_audit_head(varchar, varchar, varchar) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_append_started_audit(varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_complete_run(varchar, varchar, varchar, text, varchar, integer, text, varchar, varchar, timestamptz) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_fail_or_retry_run(varchar, varchar, varchar, varchar, timestamptz, varchar, varchar, text, varchar, integer, varchar, text, varchar, varchar, timestamptz) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_begin_expired_reclaim() TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_finish_expired_reclaim(varchar, varchar, timestamptz, varchar, varchar, varchar, integer, varchar, text, varchar, varchar, timestamptz) TO jyxia_worker;
                END IF;
            END
            $$;
            """
        )
    )


def _downgrade_pg_worker_functions_rls_and_grants() -> None:
    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_worker') THEN
                    REVOKE ALL ON ALL TABLES IN SCHEMA public FROM jyxia_worker;
                    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM jyxia_worker;
                END IF;
            END
            $$;
            """
        )
    )
    op.execute(
        sa.text(
            "DROP POLICY IF EXISTS p_processing_runs_worker_queue_definer ON public.processing_runs;"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_finish_expired_reclaim("
            "varchar, varchar, timestamptz, varchar, varchar, varchar, integer, varchar, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(sa.text("DROP FUNCTION IF EXISTS public.jyxia_worker_begin_expired_reclaim();"))
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_fail_or_retry_run("
            "varchar, varchar, varchar, varchar, timestamptz, varchar, varchar, text, varchar, integer, varchar, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_complete_run("
            "varchar, varchar, varchar, text, varchar, integer, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_append_started_audit("
            "varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_prepare_run_audit_head(varchar, varchar, varchar);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_claim_next_run(varchar, varchar, integer, varchar);"
        )
    )


def upgrade() -> None:
    bind = op.get_bind()

    with op.batch_alter_table("processing_runs", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.add_column(
            sa.Column(
                "step_type",
                sa.String(length=64),
                nullable=False,
                server_default=sa.text("'verify_object_integrity'"),
            )
        )
        batch_op.add_column(sa.Column("triggered_by_user_id", sa.String(length=36), nullable=True))
        batch_op.add_column(
            sa.Column(
                "attempt_count",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("0"),
            )
        )
        batch_op.add_column(
            sa.Column(
                "max_attempts",
                sa.Integer(),
                nullable=False,
                server_default=sa.text("5"),
            )
        )
        batch_op.add_column(sa.Column("available_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column("lease_token_hash", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("worker_id", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("last_error_code", sa.String(length=64), nullable=True))
        batch_op.add_column(sa.Column("last_error_detail", sa.String(length=512), nullable=True))
        batch_op.add_column(sa.Column("result_json", _JSON_VARIANT, nullable=True))
        batch_op.add_column(sa.Column("updated_at", sa.DateTime(timezone=True), nullable=True))

    op.execute(sa.text("UPDATE processing_runs SET available_at = created_at WHERE available_at IS NULL"))
    op.execute(
        sa.text(
            "UPDATE processing_runs SET updated_at = created_at WHERE updated_at IS NULL OR updated_at < created_at"
        )
    )

    with op.batch_alter_table("processing_runs", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.alter_column("started_at", existing_type=sa.DateTime(timezone=True), nullable=True)
        batch_op.alter_column("available_at", existing_type=sa.DateTime(timezone=True), nullable=False)
        batch_op.alter_column("updated_at", existing_type=sa.DateTime(timezone=True), nullable=False)

        batch_op.drop_constraint("ck_processing_runs_status_valid", type_="check")
        batch_op.drop_constraint("ck_processing_runs_finished_after_started", type_="check")

        batch_op.create_check_constraint("ck_processing_runs_status_valid", _NEW_STATUS_SQL)
        batch_op.create_check_constraint("ck_processing_runs_step_type_valid", _STEP_TYPE_SQL)
        batch_op.create_check_constraint("ck_processing_runs_attempt_count_nonneg", "attempt_count >= 0")
        batch_op.create_check_constraint(
            "ck_processing_runs_max_attempts_valid",
            "max_attempts >= 1 AND attempt_count <= max_attempts",
        )
        batch_op.create_check_constraint(
            "ck_processing_runs_lease_hash_hex64",
            "lease_token_hash IS NULL OR (length(trim(lease_token_hash)) = 64 AND lease_token_hash = lower(lease_token_hash))",
        )
        batch_op.create_check_constraint(
            "ck_processing_runs_error_code_min_len",
            "last_error_code IS NULL OR length(trim(last_error_code)) >= 2",
        )
        batch_op.create_check_constraint(
            "ck_processing_runs_finished_after_started",
            "finished_at IS NULL OR (started_at IS NOT NULL AND finished_at >= started_at)",
        )
        batch_op.create_check_constraint(
            "ck_processing_runs_updated_after_created",
            "updated_at >= created_at",
        )

        batch_op.create_foreign_key(
            "fk_processing_runs_triggered_by_user_id_users",
            "users",
            ["triggered_by_user_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_foreign_key(
            "fk_processing_runs_org_actor",
            "organization_memberships",
            ["organization_id", "triggered_by_user_id"],
            ["organization_id", "user_id"],
            ondelete="RESTRICT",
        )

    op.create_index(
        "ix_processing_runs_queue_claim",
        "processing_runs",
        ["status", "available_at", "created_at"],
        unique=False,
    )
    op.create_index(
        "ix_processing_runs_org_status",
        "processing_runs",
        ["organization_id", "status", "available_at"],
        unique=False,
    )
    op.create_index(
        "uq_processing_runs_active_ver_step",
        "processing_runs",
        ["organization_id", "document_version_id", "step_type"],
        unique=True,
        sqlite_where=sa.text(_ACTIVE_WHERE_SQL),
        postgresql_where=sa.text(_ACTIVE_WHERE_SQL),
    )

    if bind.dialect.name == "postgresql":
        _upgrade_pg_worker_functions_rls_and_grants()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _downgrade_pg_worker_functions_rls_and_grants()

    op.drop_index("uq_processing_runs_active_ver_step", table_name="processing_runs")
    op.drop_index("ix_processing_runs_org_status", table_name="processing_runs")
    op.drop_index("ix_processing_runs_queue_claim", table_name="processing_runs")

    op.execute(sa.text("UPDATE processing_runs SET status = 'pending' WHERE status IN ('queued', 'retry_wait')"))
    op.execute(sa.text("UPDATE processing_runs SET status = 'completed' WHERE status = 'succeeded'"))
    op.execute(sa.text("UPDATE processing_runs SET status = 'failed' WHERE status = 'cancelled'"))
    op.execute(sa.text("UPDATE processing_runs SET started_at = created_at WHERE started_at IS NULL"))
    op.execute(
        sa.text(
            "UPDATE processing_runs SET finished_at = started_at "
            "WHERE finished_at IS NOT NULL AND finished_at < started_at"
        )
    )

    with op.batch_alter_table("processing_runs", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("fk_processing_runs_org_actor", type_="foreignkey")
        batch_op.drop_constraint("fk_processing_runs_triggered_by_user_id_users", type_="foreignkey")

        batch_op.drop_constraint("ck_processing_runs_updated_after_created", type_="check")
        batch_op.drop_constraint("ck_processing_runs_finished_after_started", type_="check")
        batch_op.drop_constraint("ck_processing_runs_error_code_min_len", type_="check")
        batch_op.drop_constraint("ck_processing_runs_lease_hash_hex64", type_="check")
        batch_op.drop_constraint("ck_processing_runs_max_attempts_valid", type_="check")
        batch_op.drop_constraint("ck_processing_runs_attempt_count_nonneg", type_="check")
        batch_op.drop_constraint("ck_processing_runs_step_type_valid", type_="check")
        batch_op.drop_constraint("ck_processing_runs_status_valid", type_="check")

        batch_op.create_check_constraint("ck_processing_runs_status_valid", _OLD_STATUS_SQL)
        batch_op.create_check_constraint(
            "ck_processing_runs_finished_after_started",
            "finished_at IS NULL OR finished_at >= started_at",
        )
        batch_op.alter_column("started_at", existing_type=sa.DateTime(timezone=True), nullable=False)

        batch_op.drop_column("updated_at")
        batch_op.drop_column("result_json")
        batch_op.drop_column("last_error_detail")
        batch_op.drop_column("last_error_code")
        batch_op.drop_column("worker_id")
        batch_op.drop_column("lease_token_hash")
        batch_op.drop_column("lease_expires_at")
        batch_op.drop_column("available_at")
        batch_op.drop_column("max_attempts")
        batch_op.drop_column("attempt_count")
        batch_op.drop_column("triggered_by_user_id")
        batch_op.drop_column("step_type")
