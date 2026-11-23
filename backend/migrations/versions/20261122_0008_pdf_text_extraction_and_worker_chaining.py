"""Add extract_pdf_text pipeline step, idempotency constraints and atomic PG worker extraction RPCs.

Revision ID: 20261122_0008
Revises: 20261122_0007
Create Date: 2026-11-23 14:35:00+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20261122_0008"
down_revision = "20261122_0007"
branch_labels = None
depends_on = None

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

_NEW_STEP_TYPE_SQL = "step_type IN ('verify_object_integrity', 'extract_pdf_text')"
_OLD_STEP_TYPE_SQL = "step_type IN ('verify_object_integrity')"


def _upgrade_pg_extraction_worker_functions_and_grants() -> None:
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
                IF v_requested_step NOT IN ('any', 'verify_object_integrity', 'extract_pdf_text') THEN
                    RAISE EXCEPTION 'Worker claim rejected: unsupported step_type';
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                JOIN public.organizations AS o ON o.id = pr.organization_id
                WHERE pr.status IN ('queued', 'retry_wait')
                  AND (
                        (v_requested_step = 'any' AND pr.step_type IN ('verify_object_integrity', 'extract_pdf_text'))
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
            CREATE OR REPLACE FUNCTION public.jyxia_worker_prepare_completion_context(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar
            )
            RETURNS TABLE (
                organization_id varchar,
                document_version_id varchar,
                document_id varchar,
                case_id varchar,
                step_type varchar,
                policy_version varchar,
                triggered_by_user_id varchar,
                max_attempts integer,
                has_active_extract_run boolean,
                last_sequence integer,
                last_event_hash varchar
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
                v_org_locked varchar;
                v_doc_id varchar;
                v_case_id varchar;
                v_has_active_extract boolean;
                v_last_seq integer;
                v_last_hash varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker completion context rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker completion context rejected: invalid lease_token_hash';
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                WHERE pr.id = p_run_id
                FOR UPDATE;

                IF v_run.id IS NULL THEN
                    RAISE EXCEPTION 'Worker completion context rejected: unknown processing_run %', p_run_id;
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

                SELECT dv.document_id::varchar, d.case_id::varchar
                INTO v_doc_id, v_case_id
                FROM public.document_versions AS dv
                JOIN public.documents AS d
                  ON d.organization_id = dv.organization_id
                 AND d.id = dv.document_id
                WHERE dv.organization_id = v_run.organization_id
                  AND dv.id = v_run.document_version_id;

                SELECT EXISTS (
                    SELECT 1
                    FROM public.processing_runs AS er
                    WHERE er.organization_id = v_run.organization_id
                      AND er.document_version_id = v_run.document_version_id
                      AND er.step_type = 'extract_pdf_text'
                      AND er.status IN ('queued', 'running', 'retry_wait')
                ) INTO v_has_active_extract;

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
                    v_run.document_version_id::varchar,
                    v_doc_id::varchar,
                    v_case_id::varchar,
                    v_run.step_type::varchar,
                    v_run.policy_version::varchar,
                    v_run.triggered_by_user_id::varchar,
                    v_run.max_attempts::integer,
                    v_has_active_extract::boolean,
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
            CREATE OR REPLACE FUNCTION public.jyxia_worker_complete_integrity_and_chain_extract(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar,
                p_result_json text,
                p_audit_id varchar,
                p_audit_sequence_number integer,
                p_audit_payload_json text,
                p_audit_prev_event_hash varchar,
                p_audit_event_hash varchar,
                p_audit_created_at timestamptz,
                p_chain_run_id varchar,
                p_chain_extractor_version varchar,
                p_chain_idempotency_key varchar,
                p_chain_audit_id varchar,
                p_chain_audit_sequence_number integer,
                p_chain_audit_payload_json text,
                p_chain_audit_prev_event_hash varchar,
                p_chain_audit_event_hash varchar,
                p_chain_audit_created_at timestamptz
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            #variable_conflict use_column
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_org_locked varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
                v_active_extract_exists boolean;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker complete+chain rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker complete+chain rejected: invalid lease_token_hash';
                END IF;

                IF p_audit_prev_event_hash IS NULL OR p_audit_prev_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker complete+chain rejected: invalid prev_event_hash';
                END IF;

                IF p_audit_event_hash IS NULL OR p_audit_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker complete+chain rejected: invalid event_hash';
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

                IF v_run.step_type <> 'verify_object_integrity' THEN
                    RAISE EXCEPTION 'Only verify_object_integrity may chain extract_pdf_text atomically';
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

                IF p_chain_run_id IS NOT NULL THEN
                    SELECT EXISTS (
                        SELECT 1
                        FROM public.processing_runs AS er
                        WHERE er.organization_id = v_run.organization_id
                          AND er.document_version_id = v_run.document_version_id
                          AND er.step_type = 'extract_pdf_text'
                          AND er.status IN ('queued', 'running', 'retry_wait')
                    ) INTO v_active_extract_exists;

                    IF NOT v_active_extract_exists THEN
                        INSERT INTO public.processing_runs (
                            id,
                            organization_id,
                            document_version_id,
                            step_type,
                            triggered_by_user_id,
                            policy_version,
                            extractor_version,
                            idempotency_key,
                            status,
                            attempt_count,
                            max_attempts,
                            available_at,
                            readable,
                            readiness_state,
                            created_at,
                            updated_at
                        ) VALUES (
                            p_chain_run_id,
                            v_run.organization_id,
                            v_run.document_version_id,
                            'extract_pdf_text',
                            v_run.triggered_by_user_id,
                            v_run.policy_version,
                            p_chain_extractor_version,
                            p_chain_idempotency_key,
                            'queued',
                            0,
                            v_run.max_attempts,
                            v_now,
                            FALSE,
                            NULL,
                            v_now,
                            v_now
                        );

                        IF p_chain_audit_sequence_number <> (p_audit_sequence_number + 1) THEN
                            RAISE EXCEPTION 'Chained run audit sequence mismatch';
                        END IF;
                        IF p_chain_audit_prev_event_hash <> p_audit_event_hash THEN
                            RAISE EXCEPTION 'Chained run audit prev_event_hash mismatch';
                        END IF;
                        IF p_chain_audit_event_hash IS NULL OR p_chain_audit_event_hash !~ '^[0-9a-f]{64}$' THEN
                            RAISE EXCEPTION 'Chained run audit invalid event_hash';
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
                            p_chain_audit_id,
                            v_run.organization_id,
                            'jyxia.audit.v1',
                            p_chain_audit_sequence_number,
                            NULL,
                            'processing_run.queued',
                            'processing_run',
                            p_chain_run_id,
                            p_chain_audit_payload_json::jsonb,
                            p_chain_audit_prev_event_hash,
                            p_chain_audit_event_hash,
                            p_chain_audit_created_at
                        );
                    END IF;
                END IF;

                PERFORM pg_catalog.set_config('app.current_organization_id', '', true);
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_complete_extraction_run(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar,
                p_readable boolean,
                p_result_json text,
                p_fields_json text,
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
            #variable_conflict use_column
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_org_locked varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
                v_integrity_ok boolean;
                v_field_item jsonb;
                v_ev_item jsonb;
                v_field_id varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker extraction completion rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker extraction completion rejected: invalid lease_token_hash';
                END IF;

                IF p_audit_event_type NOT IN ('processing_run.succeeded', 'processing_run.abstained') THEN
                    RAISE EXCEPTION 'Invalid extraction audit event_type %', COALESCE(p_audit_event_type, '<null>');
                END IF;

                IF p_audit_prev_event_hash IS NULL OR p_audit_prev_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker extraction completion rejected: invalid prev_event_hash';
                END IF;

                IF p_audit_event_hash IS NULL OR p_audit_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker extraction completion rejected: invalid event_hash';
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
                    RAISE EXCEPTION 'Worker lease invalid or expired for extraction completion of %', p_run_id;
                END IF;

                IF v_run.step_type <> 'extract_pdf_text' THEN
                    RAISE EXCEPTION 'Worker extraction completion requires step_type extract_pdf_text';
                END IF;

                SELECT EXISTS (
                    SELECT 1
                    FROM public.processing_runs AS vr
                    WHERE vr.organization_id = v_run.organization_id
                      AND vr.document_version_id = v_run.document_version_id
                      AND vr.step_type = 'verify_object_integrity'
                      AND vr.status = 'succeeded'
                ) INTO v_integrity_ok;

                IF NOT v_integrity_ok THEN
                    RAISE EXCEPTION 'Extraction blocked: verify_object_integrity has not succeeded for document_version %', v_run.document_version_id;
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                FOR v_field_item IN
                    SELECT value FROM jsonb_array_elements(COALESCE(p_fields_json, '[]')::jsonb)
                LOOP
                    v_field_id := v_field_item->>'id';
                    INSERT INTO public.extracted_fields (
                        id,
                        organization_id,
                        processing_run_id,
                        document_version_id,
                        field_key,
                        raw_value,
                        normalized_value,
                        status,
                        abstained,
                        metadata_json,
                        created_at
                    ) VALUES (
                        v_field_id,
                        v_run.organization_id,
                        v_run.id,
                        v_run.document_version_id,
                        v_field_item->>'field_key',
                        v_field_item->>'raw_value',
                        v_field_item->>'normalized_value',
                        v_field_item->>'status',
                        COALESCE((v_field_item->>'abstained')::boolean, FALSE),
                        CASE
                            WHEN v_field_item->'metadata_json' IS NULL OR v_field_item->'metadata_json' = 'null'::jsonb
                            THEN NULL
                            ELSE v_field_item->'metadata_json'
                        END,
                        v_now
                    );

                    FOR v_ev_item IN
                        SELECT value FROM jsonb_array_elements(COALESCE(v_field_item->'evidences', '[]'::jsonb))
                    LOOP
                        INSERT INTO public.evidence_references (
                            id,
                            organization_id,
                            extracted_field_id,
                            document_version_id,
                            page_number,
                            bbox_x,
                            bbox_y,
                            bbox_w,
                            bbox_h,
                            quote_excerpt,
                            extraction_method,
                            created_at
                        ) VALUES (
                            v_ev_item->>'id',
                            v_run.organization_id,
                            v_field_id,
                            v_run.document_version_id,
                            (v_ev_item->>'page_number')::integer,
                            (v_ev_item->>'bbox_x')::double precision,
                            (v_ev_item->>'bbox_y')::double precision,
                            (v_ev_item->>'bbox_w')::double precision,
                            (v_ev_item->>'bbox_h')::double precision,
                            v_ev_item->>'quote_excerpt',
                            v_ev_item->>'extraction_method',
                            v_now
                        );
                    END LOOP;
                END LOOP;

                UPDATE public.processing_runs AS pr
                SET status = 'succeeded',
                    lease_expires_at = NULL,
                    lease_token_hash = NULL,
                    last_error_code = NULL,
                    last_error_detail = NULL,
                    result_json = CASE WHEN p_result_json IS NULL THEN NULL ELSE p_result_json::jsonb END,
                    readable = COALESCE(p_readable, FALSE),
                    readiness_state = NULL,
                    finished_at = GREATEST(v_now, COALESCE(v_run.started_at, v_now)),
                    updated_at = GREATEST(v_now, v_run.created_at)
                WHERE pr.id = v_run.id;

                SELECT COALESCE(MAX(ae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = v_run.organization_id;

                IF p_audit_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Worker extraction audit sequence mismatch: expected %, got %', v_expected_seq, p_audit_sequence_number;
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
                    RAISE EXCEPTION 'Worker extraction audit prev_event_hash mismatch for sequence %', p_audit_sequence_number;
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
                REVOKE ALL ON FUNCTION public.jyxia_worker_prepare_completion_context(varchar, varchar, varchar) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_complete_integrity_and_chain_extract(
                    varchar, varchar, varchar, text, varchar, integer, text, varchar, varchar, timestamptz,
                    varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_complete_extraction_run(
                    varchar, varchar, varchar, boolean, text, text, varchar, integer, varchar, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    REVOKE ALL ON FUNCTION public.jyxia_worker_prepare_completion_context(varchar, varchar, varchar) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_complete_integrity_and_chain_extract(
                        varchar, varchar, varchar, text, varchar, integer, text, varchar, varchar, timestamptz,
                        varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz
                    ) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_complete_extraction_run(
                        varchar, varchar, varchar, boolean, text, text, varchar, integer, varchar, text, varchar, varchar, timestamptz
                    ) FROM jyxia_app;
                END IF;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_worker') THEN
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_prepare_completion_context(varchar, varchar, varchar) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_complete_integrity_and_chain_extract(
                        varchar, varchar, varchar, text, varchar, integer, text, varchar, varchar, timestamptz,
                        varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz
                    ) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_complete_extraction_run(
                        varchar, varchar, varchar, boolean, text, text, varchar, integer, varchar, text, varchar, varchar, timestamptz
                    ) TO jyxia_worker;
                END IF;
            END
            $$;
            """
        )
    )


def _downgrade_pg_extraction_worker_functions_and_grants() -> None:
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_complete_extraction_run("
            "varchar, varchar, varchar, boolean, text, text, varchar, integer, varchar, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_complete_integrity_and_chain_extract("
            "varchar, varchar, varchar, text, varchar, integer, text, varchar, varchar, timestamptz, "
            "varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_prepare_completion_context(varchar, varchar, varchar);"
        )
    )

    # Restore exact 0007 jyxia_worker_claim_next_run restricting step_type to verify_object_integrity
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
                    lease_expires_at = v_now + pg_catalog.make_interval(secs => p_lease_seconds::double precision),
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


def upgrade() -> None:
    bind = op.get_bind()

    with op.batch_alter_table("processing_runs", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_processing_runs_step_type_valid", type_="check")
        batch_op.create_check_constraint("ck_processing_runs_step_type_valid", _NEW_STEP_TYPE_SQL)

    with op.batch_alter_table("extracted_fields", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.create_unique_constraint(
            "uq_extracted_fields_org_run_key",
            ["organization_id", "processing_run_id", "field_key"],
        )

    op.create_index(
        "ix_evidence_refs_org_docver_page",
        "evidence_references",
        ["organization_id", "document_version_id", "page_number"],
        unique=False,
    )

    if bind.dialect.name == "postgresql":
        _upgrade_pg_extraction_worker_functions_and_grants()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _downgrade_pg_extraction_worker_functions_and_grants()

    op.drop_index("ix_evidence_refs_org_docver_page", table_name="evidence_references")

    with op.batch_alter_table("extracted_fields", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("uq_extracted_fields_org_run_key", type_="unique")

    # Preserve historical rows and avoid partial-unique collision before restoring 0007 step constraint
    op.execute(
        sa.text(
            "UPDATE processing_runs SET status = 'cancelled' "
            "WHERE step_type = 'extract_pdf_text' "
            "AND status IN ('queued', 'running', 'retry_wait')"
        )
    )
    op.execute(
        sa.text(
            "UPDATE processing_runs SET step_type = 'verify_object_integrity' "
            "WHERE step_type = 'extract_pdf_text'"
        )
    )

    with op.batch_alter_table("processing_runs", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_processing_runs_step_type_valid", type_="check")
        batch_op.create_check_constraint("ck_processing_runs_step_type_valid", _OLD_STEP_TYPE_SQL)
