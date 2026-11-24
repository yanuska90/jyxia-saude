"""Add compare_consistency worker step, consistency_assessments tables, RLS, and PG worker RPCs.

Revision ID: 20261122_0009
Revises: 20261122_0008
Create Date: 2026-11-23 18:10:00+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20261122_0009"
down_revision = "20261122_0008"
branch_labels = None
depends_on = None

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

_NEW_STEP_TYPE_SQL = (
    "step_type IN ('verify_object_integrity', 'extract_pdf_text', 'compare_consistency')"
)
_OLD_STEP_TYPE_SQL = "step_type IN ('verify_object_integrity', 'extract_pdf_text')"

_READINESS_STATE_SQL = (
    "readiness_state IN "
    "('pendente', 'bloqueado', 'abstencao', 'conferida_com_escopo_limitado', 'conferida')"
)
_AXIS_NAME_SQL = (
    "axis_name IN ('identidade', 'procedimento_codigo', 'lateralidade', 'temporalidade')"
)
_AXIS_STATUS_SQL = (
    "status IN ('ok', 'conflito', 'abstencao', 'nao_avaliado', 'nao_aplicavel', 'pendente')"
)
_AUTO_OUTCOME_SQL = (
    "automated_axes_outcome IN "
    "('all_ok', 'conflict_detected', 'abstained', 'pending', 'limited_scope')"
)


def _upgrade_pg_consistency_security_and_rpcs() -> None:
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_forbid_consistency_mutation()
            RETURNS trigger
            LANGUAGE plpgsql
            SET search_path = pg_catalog, public
            AS $$
            BEGIN
                RAISE EXCEPTION 'Consistency assessment ledger (%) is strictly append-only', TG_TABLE_NAME;
            END;
            $$;
            """
        )
    )

    for tbl in (
        "consistency_assessments",
        "consistency_axis_results",
        "consistency_axis_evidences",
    ):
        op.execute(sa.text(f"ALTER TABLE public.{tbl} ENABLE ROW LEVEL SECURITY;"))
        op.execute(sa.text(f"ALTER TABLE public.{tbl} FORCE ROW LEVEL SECURITY;"))
        op.execute(
            sa.text(
                f"""
                CREATE POLICY p_{tbl}_tenant_isolation ON public.{tbl}
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
                f"""
                CREATE TRIGGER trg_{tbl}_append_only
                BEFORE UPDATE OR DELETE ON public.{tbl}
                FOR EACH ROW
                EXECUTE FUNCTION public.jyxia_forbid_consistency_mutation();
                """
            )
        )

    op.execute(
        sa.text(
            """
            DO $$
            BEGIN
                REVOKE ALL ON TABLE
                    public.consistency_assessments,
                    public.consistency_axis_results,
                    public.consistency_axis_evidences
                FROM PUBLIC;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    REVOKE ALL ON TABLE
                        public.consistency_assessments,
                        public.consistency_axis_results,
                        public.consistency_axis_evidences
                    FROM jyxia_app;
                    GRANT SELECT ON TABLE
                        public.consistency_assessments,
                        public.consistency_axis_results,
                        public.consistency_axis_evidences
                    TO jyxia_app;
                END IF;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_worker') THEN
                    REVOKE ALL ON TABLE
                        public.consistency_assessments,
                        public.consistency_axis_results,
                        public.consistency_axis_evidences
                    FROM jyxia_worker;
                END IF;
            END
            $$;
            """
        )
    )

    # Update claim RPC so workers claim 'compare_consistency' cleanly as well.
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
                IF v_requested_step NOT IN ('any', 'verify_object_integrity', 'extract_pdf_text', 'compare_consistency') THEN
                    RAISE EXCEPTION 'Worker claim rejected: unsupported step_type';
                END IF;

                v_now := pg_catalog.clock_timestamp();

                SELECT pr.* INTO v_run
                FROM public.processing_runs AS pr
                JOIN public.organizations AS o ON o.id = pr.organization_id
                WHERE pr.status IN ('queued', 'retry_wait')
                  AND (
                        (v_requested_step = 'any' AND pr.step_type IN ('verify_object_integrity', 'extract_pdf_text', 'compare_consistency'))
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

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_prepare_extraction_completion_context(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar
            )
            RETURNS TABLE (
                organization_id varchar,
                document_version_id varchar,
                document_id varchar,
                case_id varchar,
                policy_version varchar,
                max_attempts integer,
                should_chain_compare boolean,
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
                v_active_docs_count integer;
                v_other_active_doc_steps boolean;
                v_active_compare boolean;
                v_should_chain boolean := FALSE;
                v_last_seq integer;
                v_last_hash varchar;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker extraction context rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker extraction context rejected: invalid lease_token_hash';
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
                    RAISE EXCEPTION 'Worker lease invalid or expired for extraction %', p_run_id;
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                SELECT dv.document_id::varchar, COALESCE(v_run.case_id, d.case_id)::varchar
                INTO v_doc_id, v_case_id
                FROM public.document_versions AS dv
                JOIN public.documents AS d
                  ON d.organization_id = dv.organization_id
                 AND d.id = dv.document_id
                WHERE dv.organization_id = v_run.organization_id
                  AND dv.id = v_run.document_version_id;

                IF v_case_id IS NOT NULL THEN
                    SELECT COUNT(*) INTO v_active_docs_count
                    FROM public.documents AS d
                    WHERE d.organization_id = v_run.organization_id
                      AND d.case_id = v_case_id
                      AND d.discarded_at IS NULL;

                    SELECT EXISTS (
                        SELECT 1
                        FROM public.processing_runs AS opr
                        JOIN public.document_versions AS odw
                          ON odw.organization_id = opr.organization_id
                         AND odw.id = opr.document_version_id
                        JOIN public.documents AS od
                          ON od.organization_id = odw.organization_id
                         AND od.id = odw.document_id
                        WHERE opr.organization_id = v_run.organization_id
                          AND od.case_id = v_case_id
                          AND od.discarded_at IS NULL
                          AND opr.id <> v_run.id
                          AND opr.step_type IN ('verify_object_integrity', 'extract_pdf_text')
                          AND opr.status IN ('queued', 'running', 'retry_wait')
                    ) INTO v_other_active_doc_steps;

                    SELECT EXISTS (
                        SELECT 1
                        FROM public.processing_runs AS cpr
                        WHERE cpr.organization_id = v_run.organization_id
                          AND cpr.case_id = v_case_id
                          AND cpr.step_type = 'compare_consistency'
                          AND cpr.status IN ('queued', 'running', 'retry_wait')
                    ) INTO v_active_compare;

                    v_should_chain := (
                        v_active_docs_count >= 2
                        AND NOT v_other_active_doc_steps
                        AND NOT v_active_compare
                    );
                END IF;

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
                    v_run.policy_version::varchar,
                    v_run.max_attempts::integer,
                    v_should_chain::boolean,
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
            CREATE OR REPLACE FUNCTION public.jyxia_worker_complete_extraction_and_chain_compare(
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
                p_audit_created_at timestamptz,
                p_chain_run_id varchar,
                p_chain_case_id varchar,
                p_chain_engine_version varchar,
                p_chain_policy_version varchar,
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
                v_integrity_ok boolean;
                v_other_active_doc_steps boolean;
                v_active_compare boolean;
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
                    RAISE EXCEPTION 'Worker extraction+chain rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker extraction+chain rejected: invalid lease_token_hash';
                END IF;

                IF p_audit_event_type NOT IN ('processing_run.succeeded', 'processing_run.abstained') THEN
                    RAISE EXCEPTION 'Invalid extraction audit event_type %', COALESCE(p_audit_event_type, '<null>');
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
                    RAISE EXCEPTION 'Worker extraction+chain requires step_type extract_pdf_text';
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
                    RAISE EXCEPTION 'Extraction blocked: verify_object_integrity has not succeeded';
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
                        id, organization_id, processing_run_id, document_version_id,
                        field_key, raw_value, normalized_value, status, abstained,
                        metadata_json, created_at
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
                            THEN NULL ELSE v_field_item->'metadata_json'
                        END,
                        v_now
                    );

                    FOR v_ev_item IN
                        SELECT value FROM jsonb_array_elements(COALESCE(v_field_item->'evidences', '[]'::jsonb))
                    LOOP
                        INSERT INTO public.evidence_references (
                            id, organization_id, extracted_field_id, document_version_id,
                            page_number, bbox_x, bbox_y, bbox_w, bbox_h,
                            quote_excerpt, extraction_method, created_at
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
                    id, organization_id, schema_version, sequence_number, actor_user_id,
                    event_type, target_entity_type, target_entity_id, payload_json,
                    prev_event_hash, event_hash, created_at
                ) VALUES (
                    p_audit_id, v_run.organization_id, 'jyxia.audit.v1', p_audit_sequence_number, NULL,
                    p_audit_event_type, 'processing_run', v_run.id, p_audit_payload_json::jsonb,
                    p_audit_prev_event_hash, p_audit_event_hash, p_audit_created_at
                );

                SELECT EXISTS (
                    SELECT 1
                    FROM public.processing_runs AS opr
                    JOIN public.document_versions AS odw
                      ON odw.organization_id = opr.organization_id
                     AND odw.id = opr.document_version_id
                    JOIN public.documents AS od
                      ON od.organization_id = odw.organization_id
                     AND od.id = odw.document_id
                    WHERE opr.organization_id = v_run.organization_id
                      AND od.case_id = p_chain_case_id
                      AND od.discarded_at IS NULL
                      AND opr.id <> v_run.id
                      AND opr.step_type IN ('verify_object_integrity', 'extract_pdf_text')
                      AND opr.status IN ('queued', 'running', 'retry_wait')
                ) INTO v_other_active_doc_steps;

                SELECT EXISTS (
                    SELECT 1
                    FROM public.processing_runs AS cpr
                    WHERE cpr.organization_id = v_run.organization_id
                      AND cpr.case_id = p_chain_case_id
                      AND cpr.step_type = 'compare_consistency'
                      AND cpr.status IN ('queued', 'running', 'retry_wait')
                ) INTO v_active_compare;

                IF NOT v_other_active_doc_steps AND NOT v_active_compare THEN
                    INSERT INTO public.processing_runs (
                        id, organization_id, document_version_id, case_id, step_type,
                        triggered_by_user_id, policy_version, extractor_version,
                        idempotency_key, status, attempt_count, max_attempts,
                        available_at, readable, created_at, updated_at
                    ) VALUES (
                        p_chain_run_id, v_run.organization_id, v_run.document_version_id,
                        p_chain_case_id, 'compare_consistency', NULL,
                        p_chain_policy_version, p_chain_engine_version,
                        p_chain_idempotency_key, 'queued', 0, v_run.max_attempts,
                        v_now, FALSE, v_now, v_now
                    );

                    IF p_chain_audit_sequence_number <> (p_audit_sequence_number + 1) THEN
                        RAISE EXCEPTION 'Chained compare audit sequence mismatch';
                    END IF;
                    IF p_chain_audit_prev_event_hash <> p_audit_event_hash THEN
                        RAISE EXCEPTION 'Chained compare audit prev hash mismatch';
                    END IF;

                    INSERT INTO public.audit_events (
                        id, organization_id, schema_version, sequence_number, actor_user_id,
                        event_type, target_entity_type, target_entity_id, payload_json,
                        prev_event_hash, event_hash, created_at
                    ) VALUES (
                        p_chain_audit_id, v_run.organization_id, 'jyxia.audit.v1',
                        p_chain_audit_sequence_number, NULL, 'processing_run.queued',
                        'processing_run', p_chain_run_id, p_chain_audit_payload_json::jsonb,
                        p_chain_audit_prev_event_hash, p_chain_audit_event_hash, p_chain_audit_created_at
                    );
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
            CREATE OR REPLACE FUNCTION public.jyxia_worker_prepare_case_comparison_context(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar
            )
            RETURNS text
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
                v_case_row public.document_cases%ROWTYPE;
                v_last_audit_seq integer;
                v_last_audit_hash varchar;
                v_last_assess_seq integer;
                v_docs_json jsonb;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker comparison context rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker comparison context rejected: invalid lease_token_hash';
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
                    RAISE EXCEPTION 'Worker lease invalid or expired for comparison %', p_run_id;
                END IF;

                IF v_run.step_type <> 'compare_consistency' THEN
                    RAISE EXCEPTION 'Worker comparison context requires step_type compare_consistency';
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                SELECT dc.* INTO v_case_row
                FROM public.document_cases AS dc
                WHERE dc.organization_id = v_run.organization_id
                  AND dc.id = COALESCE(
                        v_run.case_id,
                        (
                            SELECT d.case_id
                            FROM public.document_versions AS dv
                            JOIN public.documents AS d
                              ON d.organization_id = dv.organization_id
                             AND d.id = dv.document_id
                            WHERE dv.organization_id = v_run.organization_id
                              AND dv.id = v_run.document_version_id
                        )
                  );

                IF v_case_row.id IS NULL THEN
                    RAISE EXCEPTION 'DocumentCase not found for compare_consistency run %', p_run_id;
                END IF;

                SELECT COALESCE(
                    jsonb_agg(
                        jsonb_build_object(
                            'document_id', d.id,
                            'document_kind', d.document_kind,
                            'document_subfamily', d.document_subfamily,
                            'source_label', d.source_label,
                            'quarantined', d.quarantined,
                            'discarded_at', d.discarded_at,
                            'versions', COALESCE((
                                SELECT jsonb_agg(
                                    jsonb_build_object(
                                        'version_id', dv.id,
                                        'document_id', dv.document_id,
                                        'version_number', dv.version_number,
                                        'sha256_hex', dv.sha256_hex,
                                        'mime_type', dv.mime_type,
                                        'created_at', dv.created_at,
                                        'is_current', dv.is_current,
                                        'superseded_by_version_id', dv.superseded_by_version_id,
                                        'integrity_status', (
                                            SELECT vrun.status FROM public.processing_runs AS vrun
                                            WHERE vrun.organization_id = dv.organization_id
                                              AND vrun.document_version_id = dv.id
                                              AND vrun.step_type = 'verify_object_integrity'
                                            ORDER BY vrun.created_at DESC, vrun.id DESC
                                            LIMIT 1
                                        ),
                                        'latest_extract', (
                                            SELECT jsonb_build_object(
                                                'run_id', erun.id,
                                                'status', erun.status,
                                                'extractor_version', erun.extractor_version,
                                                'readable', erun.readable,
                                                'outcome', erun.result_json->>'outcome'
                                            )
                                            FROM public.processing_runs AS erun
                                            WHERE erun.organization_id = dv.organization_id
                                              AND erun.document_version_id = dv.id
                                              AND erun.step_type = 'extract_pdf_text'
                                            ORDER BY
                                                CASE WHEN erun.status = 'succeeded' THEN 0 ELSE 1 END,
                                                erun.created_at DESC,
                                                erun.id DESC
                                            LIMIT 1
                                        ),
                                        'extracted_fields', COALESCE((
                                            SELECT jsonb_agg(
                                                jsonb_build_object(
                                                    'extracted_field_id', ef.id,
                                                    'organization_id', ef.organization_id,
                                                    'document_version_id', ef.document_version_id,
                                                    'processing_run_id', ef.processing_run_id,
                                                    'field_key', ef.field_key,
                                                    'raw_value', ef.raw_value,
                                                    'normalized_value', ef.normalized_value,
                                                    'status', ef.status,
                                                    'abstained', ef.abstained,
                                                    'metadata_json', COALESCE(ef.metadata_json, '{}'::jsonb),
                                                    'evidences', COALESCE((
                                                        SELECT jsonb_agg(
                                                            jsonb_build_object(
                                                                'evidence_id', ev.id,
                                                                'organization_id', ev.organization_id,
                                                                'document_version_id', ev.document_version_id,
                                                                'extracted_field_id', ev.extracted_field_id,
                                                                'page_number', ev.page_number,
                                                                'bbox_x', ev.bbox_x,
                                                                'bbox_y', ev.bbox_y,
                                                                'bbox_w', ev.bbox_w,
                                                                'bbox_h', ev.bbox_h,
                                                                'quote_excerpt', ev.quote_excerpt,
                                                                'extraction_method', ev.extraction_method
                                                            ) ORDER BY ev.page_number ASC, ev.id ASC
                                                        )
                                                        FROM public.evidence_references AS ev
                                                        WHERE ev.organization_id = ef.organization_id
                                                          AND ev.document_version_id = ef.document_version_id
                                                          AND ev.extracted_field_id = ef.id
                                                    ), '[]'::jsonb)
                                                ) ORDER BY ef.field_key ASC
                                            )
                                            FROM public.extracted_fields AS ef
                                            WHERE ef.organization_id = dv.organization_id
                                              AND ef.document_version_id = dv.id
                                              AND ef.processing_run_id = (
                                                  SELECT er2.id FROM public.processing_runs AS er2
                                                  WHERE er2.organization_id = dv.organization_id
                                                    AND er2.document_version_id = dv.id
                                                    AND er2.step_type = 'extract_pdf_text'
                                                    AND er2.status = 'succeeded'
                                                  ORDER BY er2.created_at DESC, er2.id DESC
                                                  LIMIT 1
                                              )
                                        ), '[]'::jsonb),
                                        'human_reviews', COALESCE((
                                            SELECT jsonb_agg(
                                                jsonb_build_object(
                                                    'review_id', hr.id,
                                                    'document_version_id', hr.document_version_id,
                                                    'action_type', hr.action_type,
                                                    'field_key', hr.field_key,
                                                    'policy_version', hr.policy_version,
                                                    'created_at', hr.created_at
                                                ) ORDER BY hr.created_at ASC, hr.id ASC
                                            )
                                            FROM public.human_reviews AS hr
                                            WHERE hr.organization_id = dv.organization_id
                                              AND hr.document_version_id = dv.id
                                        ), '[]'::jsonb)
                                    ) ORDER BY dv.version_number ASC, dv.created_at ASC, dv.id ASC
                                )
                                FROM public.document_versions AS dv
                                WHERE dv.organization_id = d.organization_id
                                  AND dv.document_id = d.id
                            ), '[]'::jsonb)
                        ) ORDER BY d.id ASC
                    ),
                    '[]'::jsonb
                )
                INTO v_docs_json
                FROM public.documents AS d
                WHERE d.organization_id = v_run.organization_id
                  AND d.case_id = v_case_row.id;

                SELECT COALESCE(MAX(ae.sequence_number), 0) INTO v_last_audit_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = v_run.organization_id;

                IF v_last_audit_seq = 0 THEN
                    v_last_audit_hash := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_last_audit_hash
                    FROM public.audit_events AS ae
                    WHERE ae.organization_id = v_run.organization_id
                      AND ae.sequence_number = v_last_audit_seq;
                END IF;

                SELECT COALESCE(MAX(ca.assessment_sequence), 0) INTO v_last_assess_seq
                FROM public.consistency_assessments AS ca
                WHERE ca.organization_id = v_run.organization_id
                  AND ca.case_id = v_case_row.id;

                PERFORM pg_catalog.set_config('app.current_organization_id', '', true);

                RETURN jsonb_build_object(
                    'organization_id', v_run.organization_id,
                    'case_id', v_case_row.id,
                    'case_code', v_case_row.case_code,
                    'procedure_reference', v_case_row.procedure_reference,
                    'declared_laterality', v_case_row.declared_laterality,
                    'last_assessment_sequence', v_last_assess_seq,
                    'last_audit_sequence', v_last_audit_seq,
                    'last_audit_event_hash', v_last_audit_hash,
                    'documents', v_docs_json
                )::text;
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_worker_complete_comparison_run(
                p_run_id varchar,
                p_worker_id varchar,
                p_lease_token_hash varchar,
                p_readiness_state varchar,
                p_axes_summary_json text,
                p_result_json text,
                p_assessment_json text,
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
            #variable_conflict use_column
            DECLARE
                v_owner_role varchar;
                v_now timestamptz;
                v_run public.processing_runs%ROWTYPE;
                v_org_locked varchar;
                v_case_id varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
                v_expected_assess_seq integer;
                v_assess jsonb;
                v_axis_item jsonb;
                v_ev_link jsonb;
            BEGIN
                SELECT r.rolname INTO v_owner_role
                FROM pg_catalog.pg_class AS c
                JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace
                JOIN pg_catalog.pg_roles AS r ON r.oid = c.relowner
                WHERE n.nspname = 'public' AND c.relname = 'processing_runs';

                IF session_user <> 'jyxia_worker' AND session_user <> v_owner_role THEN
                    RAISE EXCEPTION 'Worker comparison completion rejected for session_user %', session_user;
                END IF;

                IF p_lease_token_hash IS NULL OR p_lease_token_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker comparison completion rejected: invalid lease_token_hash';
                END IF;

                IF p_audit_prev_event_hash IS NULL OR p_audit_prev_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker comparison completion rejected: invalid prev_event_hash';
                END IF;

                IF p_audit_event_hash IS NULL OR p_audit_event_hash !~ '^[0-9a-f]{64}$' THEN
                    RAISE EXCEPTION 'Worker comparison completion rejected: invalid event_hash';
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
                    RAISE EXCEPTION 'Worker lease invalid or expired for comparison completion of %', p_run_id;
                END IF;

                IF v_run.step_type <> 'compare_consistency' THEN
                    RAISE EXCEPTION 'Worker comparison completion requires step_type compare_consistency';
                END IF;

                SELECT o.id INTO v_org_locked
                FROM public.organizations AS o
                WHERE o.id = v_run.organization_id
                FOR UPDATE;

                PERFORM pg_catalog.set_config('app.current_organization_id', v_run.organization_id, true);

                v_assess := p_assessment_json::jsonb;
                v_case_id := COALESCE(v_assess->>'case_id', v_run.case_id);

                SELECT COALESCE(MAX(ca.assessment_sequence), 0) + 1 INTO v_expected_assess_seq
                FROM public.consistency_assessments AS ca
                WHERE ca.organization_id = v_run.organization_id
                  AND ca.case_id = v_case_id;

                IF (v_assess->>'assessment_sequence')::integer <> v_expected_assess_seq THEN
                    RAISE EXCEPTION 'Assessment sequence mismatch: expected %, got %', v_expected_assess_seq, v_assess->>'assessment_sequence';
                END IF;

                INSERT INTO public.consistency_assessments (
                    id, organization_id, case_id, processing_run_id, assessment_sequence,
                    engine_name, engine_version, policy_version, input_fingerprint_sha256,
                    automated_axes_outcome, readiness_state, human_review_completed,
                    human_review_required, administrative_only, clinical_approval,
                    compared_documents_count, compared_snapshot_json, extraction_run_ids_json,
                    limitations_json, summary_json, assessed_at, created_at
                ) VALUES (
                    v_assess->>'id',
                    v_run.organization_id,
                    v_case_id,
                    v_run.id,
                    (v_assess->>'assessment_sequence')::integer,
                    v_assess->>'engine_name',
                    v_assess->>'engine_version',
                    v_assess->>'policy_version',
                    v_assess->>'input_fingerprint_sha256',
                    v_assess->>'automated_axes_outcome',
                    p_readiness_state,
                    (v_assess->>'human_review_completed')::boolean,
                    COALESCE((v_assess->>'human_review_required')::boolean, TRUE),
                    TRUE,
                    FALSE,
                    (v_assess->>'compared_documents_count')::integer,
                    v_assess->'compared_snapshot_json',
                    v_assess->'extraction_run_ids_json',
                    v_assess->'limitations_json',
                    v_assess->'summary_json',
                    v_now,
                    v_now
                );

                FOR v_axis_item IN
                    SELECT value FROM jsonb_array_elements(COALESCE(v_assess->'axes', '[]'::jsonb))
                LOOP
                    INSERT INTO public.consistency_axis_results (
                        id, organization_id, case_id, assessment_id, axis_name, status,
                        rule_code, justification, fields_used_json, compared_document_ids_json,
                        compared_version_ids_json, evidence_reference_ids_json,
                        comparison_items_json, limitations_json, engine_version,
                        administrative_only, clinical_approval, created_at
                    ) VALUES (
                        v_axis_item->>'id',
                        v_run.organization_id,
                        v_case_id,
                        v_assess->>'id',
                        v_axis_item->>'axis_name',
                        v_axis_item->>'status',
                        v_axis_item->>'rule_code',
                        v_axis_item->>'justification',
                        v_axis_item->'fields_used_json',
                        v_axis_item->'compared_document_ids_json',
                        v_axis_item->'compared_version_ids_json',
                        v_axis_item->'evidence_reference_ids_json',
                        v_axis_item->'comparison_items_json',
                        v_axis_item->'limitations_json',
                        v_axis_item->>'engine_version',
                        TRUE,
                        FALSE,
                        v_now
                    );

                    FOR v_ev_link IN
                        SELECT value FROM jsonb_array_elements(COALESCE(v_axis_item->'evidence_links', '[]'::jsonb))
                    LOOP
                        INSERT INTO public.consistency_axis_evidences (
                            id, organization_id, assessment_id, axis_result_id,
                            document_version_id, extracted_field_id, evidence_reference_id, created_at
                        ) VALUES (
                            v_ev_link->>'id',
                            v_run.organization_id,
                            v_assess->>'id',
                            v_axis_item->>'id',
                            v_ev_link->>'document_version_id',
                            v_ev_link->>'extracted_field_id',
                            v_ev_link->>'evidence_reference_id',
                            v_now
                        );
                    END LOOP;
                END LOOP;

                UPDATE public.document_cases AS dc
                SET readiness_state = p_readiness_state,
                    updated_at = GREATEST(v_now, dc.created_at)
                WHERE dc.organization_id = v_run.organization_id
                  AND dc.id = v_case_id;

                UPDATE public.processing_runs AS pr
                SET status = 'succeeded',
                    lease_expires_at = NULL,
                    lease_token_hash = NULL,
                    last_error_code = NULL,
                    last_error_detail = NULL,
                    readiness_state = p_readiness_state,
                    axes_summary = CASE WHEN p_axes_summary_json IS NULL THEN NULL ELSE p_axes_summary_json::jsonb END,
                    result_json = CASE WHEN p_result_json IS NULL THEN NULL ELSE p_result_json::jsonb END,
                    readable = TRUE,
                    finished_at = GREATEST(v_now, COALESCE(v_run.started_at, v_now)),
                    updated_at = GREATEST(v_now, v_run.created_at)
                WHERE pr.id = v_run.id;

                SELECT COALESCE(MAX(ae.sequence_number), 0) + 1 INTO v_expected_seq
                FROM public.audit_events AS ae
                WHERE ae.organization_id = v_run.organization_id;

                IF p_audit_sequence_number <> v_expected_seq THEN
                    RAISE EXCEPTION 'Worker comparison audit sequence mismatch: expected %, got %', v_expected_seq, p_audit_sequence_number;
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
                    RAISE EXCEPTION 'Worker comparison audit prev_event_hash mismatch for sequence %', p_audit_sequence_number;
                END IF;

                INSERT INTO public.audit_events (
                    id, organization_id, schema_version, sequence_number, actor_user_id,
                    event_type, target_entity_type, target_entity_id, payload_json,
                    prev_event_hash, event_hash, created_at
                ) VALUES (
                    p_audit_id, v_run.organization_id, 'jyxia.audit.v1', p_audit_sequence_number, NULL,
                    'processing_run.succeeded', 'processing_run', v_run.id, p_audit_payload_json::jsonb,
                    p_audit_prev_event_hash, p_audit_event_hash, p_audit_created_at
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
                REVOKE ALL ON FUNCTION public.jyxia_worker_prepare_extraction_completion_context(varchar, varchar, varchar) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_complete_extraction_and_chain_compare(
                    varchar, varchar, varchar, boolean, text, text, varchar, integer, varchar, text, varchar, varchar, timestamptz,
                    varchar, varchar, varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_prepare_case_comparison_context(varchar, varchar, varchar) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_worker_complete_comparison_run(
                    varchar, varchar, varchar, varchar, text, text, text, varchar, integer, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    REVOKE ALL ON FUNCTION public.jyxia_worker_prepare_extraction_completion_context(varchar, varchar, varchar) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_complete_extraction_and_chain_compare(
                        varchar, varchar, varchar, boolean, text, text, varchar, integer, varchar, text, varchar, varchar, timestamptz,
                        varchar, varchar, varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz
                    ) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_prepare_case_comparison_context(varchar, varchar, varchar) FROM jyxia_app;
                    REVOKE ALL ON FUNCTION public.jyxia_worker_complete_comparison_run(
                        varchar, varchar, varchar, varchar, text, text, text, varchar, integer, text, varchar, varchar, timestamptz
                    ) FROM jyxia_app;
                END IF;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_worker') THEN
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_prepare_extraction_completion_context(varchar, varchar, varchar) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_complete_extraction_and_chain_compare(
                        varchar, varchar, varchar, boolean, text, text, varchar, integer, varchar, text, varchar, varchar, timestamptz,
                        varchar, varchar, varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz
                    ) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_prepare_case_comparison_context(varchar, varchar, varchar) TO jyxia_worker;
                    GRANT EXECUTE ON FUNCTION public.jyxia_worker_complete_comparison_run(
                        varchar, varchar, varchar, varchar, text, text, text, varchar, integer, text, varchar, varchar, timestamptz
                    ) TO jyxia_worker;
                END IF;
            END
            $$;
            """
        )
    )


def _downgrade_pg_consistency_security_and_rpcs() -> None:
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_complete_comparison_run("
            "varchar, varchar, varchar, varchar, text, text, text, varchar, integer, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_prepare_case_comparison_context(varchar, varchar, varchar);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_complete_extraction_and_chain_compare("
            "varchar, varchar, varchar, boolean, text, text, varchar, integer, varchar, text, varchar, varchar, timestamptz, "
            "varchar, varchar, varchar, varchar, varchar, varchar, integer, text, varchar, varchar, timestamptz);"
        )
    )
    op.execute(
        sa.text(
            "DROP FUNCTION IF EXISTS public.jyxia_worker_prepare_extraction_completion_context(varchar, varchar, varchar);"
        )
    )

    # Restore exact 0008 jyxia_worker_claim_next_run restricting step_type to verify & extract
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
                    dv.document_id::varchar, d.case_id::varchar, dv.sha256_hex::varchar,
                    dv.mime_type::varchar, dv.byte_size::bigint, dv.page_count::integer,
                    dv.storage_driver::varchar, dv.storage_key::varchar
                INTO v_doc_id, v_case_id, v_sha256, v_mime, v_byte_size, v_page_count, v_storage_driver, v_storage_key
                FROM public.document_versions AS dv
                JOIN public.documents AS d ON d.organization_id = dv.organization_id AND d.id = dv.document_id
                WHERE dv.organization_id = v_run.organization_id AND dv.id = v_run.document_version_id;

                SELECT o.id INTO v_org_locked FROM public.organizations AS o WHERE o.id = v_run.organization_id FOR UPDATE;
                SELECT COALESCE(MAX(ae.sequence_number), 0) INTO v_last_seq
                FROM public.audit_events AS ae WHERE ae.organization_id = v_run.organization_id;

                IF v_last_seq = 0 THEN
                    v_last_hash := repeat('0', 64);
                ELSE
                    SELECT ae.event_hash INTO v_last_hash FROM public.audit_events AS ae
                    WHERE ae.organization_id = v_run.organization_id AND ae.sequence_number = v_last_seq;
                END IF;

                PERFORM pg_catalog.set_config('app.current_organization_id', '', true);

                RETURN QUERY SELECT
                    v_run.id::varchar, v_run.organization_id::varchar, v_run.document_version_id::varchar,
                    v_doc_id::varchar, v_case_id::varchar, v_run.step_type::varchar, v_run.policy_version::varchar,
                    v_run.extractor_version::varchar, v_run.idempotency_key::varchar, v_run.triggered_by_user_id::varchar,
                    v_run.attempt_count::integer, v_run.max_attempts::integer, v_run.started_at::timestamptz,
                    v_run.available_at::timestamptz, v_run.lease_expires_at::timestamptz, v_sha256::varchar,
                    v_mime::varchar, v_byte_size::bigint, v_page_count::integer, v_storage_driver::varchar,
                    v_storage_key::varchar, v_last_seq::integer, v_last_hash::varchar;
            END;
            $$;
            """
        )
    )

    for tbl in (
        "consistency_axis_evidences",
        "consistency_axis_results",
        "consistency_assessments",
    ):
        op.execute(sa.text(f"DROP TRIGGER IF EXISTS trg_{tbl}_append_only ON public.{tbl};"))
        op.execute(sa.text(f"DROP POLICY IF EXISTS p_{tbl}_tenant_isolation ON public.{tbl};"))

    op.execute(sa.text("DROP FUNCTION IF EXISTS public.jyxia_forbid_consistency_mutation();"))


def upgrade() -> None:
    bind = op.get_bind()
    json_type = sa.JSON() if bind.dialect.name == "sqlite" else sa.dialects.postgresql.JSONB()

    with op.batch_alter_table("processing_runs", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column("case_id", sa.String(length=36), nullable=True))
        batch_op.drop_constraint("ck_processing_runs_step_type_valid", type_="check")
        batch_op.create_check_constraint("ck_processing_runs_step_type_valid", _NEW_STEP_TYPE_SQL)
        batch_op.create_foreign_key(
            "fk_processing_runs_org_case",
            "document_cases",
            ["organization_id", "case_id"],
            ["organization_id", "id"],
            ondelete="RESTRICT",
        )

    # Backfill case_id cleanly on existing document_version runs
    op.execute(
        sa.text(
            "UPDATE processing_runs SET case_id = ("
            "SELECT d.case_id FROM document_versions AS dv "
            "JOIN documents AS d ON d.organization_id = dv.organization_id AND d.id = dv.document_id "
            "WHERE dv.organization_id = processing_runs.organization_id "
            "AND dv.id = processing_runs.document_version_id)"
        )
    )

    op.create_index(
        "ix_processing_runs_org_case",
        "processing_runs",
        ["organization_id", "case_id", "step_type", "created_at"],
        unique=False,
    )
    op.create_index(
        "uq_processing_runs_active_case_compare",
        "processing_runs",
        ["organization_id", "case_id"],
        unique=True,
        sqlite_where=sa.text(
            "step_type = 'compare_consistency' AND status IN ('queued', 'running', 'retry_wait') AND case_id IS NOT NULL"
        ),
        postgresql_where=sa.text(
            "step_type = 'compare_consistency' AND status IN ('queued', 'running', 'retry_wait') AND case_id IS NOT NULL"
        ),
    )

    op.create_table(
        "consistency_assessments",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("processing_run_id", sa.String(length=36), nullable=False),
        sa.Column("assessment_sequence", sa.Integer(), nullable=False),
        sa.Column("engine_name", sa.String(length=64), nullable=False),
        sa.Column("engine_version", sa.String(length=64), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("input_fingerprint_sha256", sa.String(length=64), nullable=False),
        sa.Column("automated_axes_outcome", sa.String(length=64), nullable=False),
        sa.Column("readiness_state", sa.String(length=64), nullable=False),
        sa.Column("human_review_completed", sa.Boolean(), nullable=False),
        sa.Column("human_review_required", sa.Boolean(), nullable=False),
        sa.Column("administrative_only", sa.Boolean(), nullable=False),
        sa.Column("clinical_approval", sa.Boolean(), nullable=False),
        sa.Column("compared_documents_count", sa.Integer(), nullable=False),
        sa.Column("compared_snapshot_json", json_type, nullable=False),
        sa.Column("extraction_run_ids_json", json_type, nullable=False),
        sa.Column("limitations_json", json_type, nullable=False),
        sa.Column("summary_json", json_type, nullable=False),
        sa.Column("assessed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("assessment_sequence >= 1", name="ck_consistency_assessments_assessment_sequence_positive"),
        sa.CheckConstraint(
            "length(trim(input_fingerprint_sha256)) = 64 "
            "AND input_fingerprint_sha256 = lower(input_fingerprint_sha256)",
            name="ck_consistency_assessments_input_fingerprint_hex64",
        ),
        sa.CheckConstraint(_AUTO_OUTCOME_SQL, name="ck_consistency_assessments_automated_outcome_valid"),
        sa.CheckConstraint(_READINESS_STATE_SQL, name="ck_consistency_assessments_readiness_state_valid"),
        sa.CheckConstraint("compared_documents_count >= 0", name="ck_consistency_assessments_compared_docs_nonneg"),
        sa.CheckConstraint("administrative_only = TRUE", name="ck_consistency_assessments_administrative_only_true"),
        sa.CheckConstraint("clinical_approval = FALSE", name="ck_consistency_assessments_clinical_approval_false"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], name="fk_consistency_assessments_organization_id_organizations", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["organization_id", "case_id"],
            ["document_cases.organization_id", "document_cases.id"],
            name="fk_consistency_assessments_org_case",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "processing_run_id"],
            ["processing_runs.organization_id", "processing_runs.id"],
            name="fk_consistency_assessments_org_run",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_consistency_assessments"),
        sa.UniqueConstraint("organization_id", "id", name="uq_consistency_assessments_org_id"),
        sa.UniqueConstraint("organization_id", "case_id", "id", name="uq_consistency_assessments_org_case_id"),
        sa.UniqueConstraint("organization_id", "processing_run_id", name="uq_consistency_assessments_org_run"),
        sa.UniqueConstraint(
            "organization_id", "case_id", "assessment_sequence", name="uq_consistency_assessments_org_case_seq"
        ),
    )
    op.create_index(
        "ix_consistency_assessments_org_case_seq",
        "consistency_assessments",
        ["organization_id", "case_id", "assessment_sequence"],
        unique=False,
    )
    op.create_index(
        "ix_consistency_assessments_org_fingerprint",
        "consistency_assessments",
        ["organization_id", "case_id", "input_fingerprint_sha256"],
        unique=False,
    )

    op.create_table(
        "consistency_axis_results",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("axis_name", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("rule_code", sa.String(length=96), nullable=False),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("fields_used_json", json_type, nullable=False),
        sa.Column("compared_document_ids_json", json_type, nullable=False),
        sa.Column("compared_version_ids_json", json_type, nullable=False),
        sa.Column("evidence_reference_ids_json", json_type, nullable=False),
        sa.Column("comparison_items_json", json_type, nullable=False),
        sa.Column("limitations_json", json_type, nullable=False),
        sa.Column("engine_version", sa.String(length=64), nullable=False),
        sa.Column("administrative_only", sa.Boolean(), nullable=False),
        sa.Column("clinical_approval", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(_AXIS_NAME_SQL, name="ck_consistency_axis_results_axis_name_valid"),
        sa.CheckConstraint(_AXIS_STATUS_SQL, name="ck_consistency_axis_results_status_valid"),
        sa.CheckConstraint("length(trim(rule_code)) >= 3", name="ck_consistency_axis_results_rule_code_min_len"),
        sa.CheckConstraint("length(trim(justification)) >= 5", name="ck_consistency_axis_results_justification_min_len"),
        sa.CheckConstraint("administrative_only = TRUE", name="ck_consistency_axis_results_administrative_only_true"),
        sa.CheckConstraint("clinical_approval = FALSE", name="ck_consistency_axis_results_clinical_approval_false"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], name="fk_consistency_axis_results_organization_id_organizations", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["organization_id", "case_id", "assessment_id"],
            [
                "consistency_assessments.organization_id",
                "consistency_assessments.case_id",
                "consistency_assessments.id",
            ],
            name="fk_consistency_axis_org_case_assess",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_consistency_axis_results"),
        sa.UniqueConstraint("organization_id", "id", name="uq_consistency_axis_org_id"),
        sa.UniqueConstraint("organization_id", "assessment_id", "id", name="uq_consistency_axis_org_assess_id"),
        sa.UniqueConstraint("organization_id", "assessment_id", "axis_name", name="uq_consistency_axis_org_assess_axis"),
    )
    op.create_index(
        "ix_consistency_axis_org_assess",
        "consistency_axis_results",
        ["organization_id", "assessment_id"],
        unique=False,
    )

    op.create_table(
        "consistency_axis_evidences",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("assessment_id", sa.String(length=36), nullable=False),
        sa.Column("axis_result_id", sa.String(length=36), nullable=False),
        sa.Column("document_version_id", sa.String(length=36), nullable=False),
        sa.Column("extracted_field_id", sa.String(length=36), nullable=False),
        sa.Column("evidence_reference_id", sa.String(length=36), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], name="fk_consistency_axis_evidences_organization_id_organizations", ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["organization_id", "assessment_id", "axis_result_id"],
            [
                "consistency_axis_results.organization_id",
                "consistency_axis_results.assessment_id",
                "consistency_axis_results.id",
            ],
            name="fk_consistency_axis_ev_axis_result",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "document_version_id", "extracted_field_id"],
            [
                "extracted_fields.organization_id",
                "extracted_fields.document_version_id",
                "extracted_fields.id",
            ],
            name="fk_consistency_axis_ev_field",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "document_version_id", "evidence_reference_id"],
            [
                "evidence_references.organization_id",
                "evidence_references.document_version_id",
                "evidence_references.id",
            ],
            name="fk_consistency_axis_ev_ref",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_consistency_axis_evidences"),
        sa.UniqueConstraint(
            "organization_id",
            "axis_result_id",
            "evidence_reference_id",
            name="uq_consistency_axis_ev_link",
        ),
    )
    op.create_index(
        "ix_consistency_axis_ev_org_axis",
        "consistency_axis_evidences",
        ["organization_id", "axis_result_id"],
        unique=False,
    )

    if bind.dialect.name == "postgresql":
        _upgrade_pg_consistency_security_and_rpcs()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _downgrade_pg_consistency_security_and_rpcs()

    op.drop_index("ix_consistency_axis_ev_org_axis", table_name="consistency_axis_evidences")
    op.drop_table("consistency_axis_evidences")

    op.drop_index("ix_consistency_axis_org_assess", table_name="consistency_axis_results")
    op.drop_table("consistency_axis_results")

    op.drop_index("ix_consistency_assessments_org_fingerprint", table_name="consistency_assessments")
    op.drop_index("ix_consistency_assessments_org_case_seq", table_name="consistency_assessments")
    op.drop_table("consistency_assessments")

    op.drop_index("uq_processing_runs_active_case_compare", table_name="processing_runs")
    op.drop_index("ix_processing_runs_org_case", table_name="processing_runs")

    # Preserve non-0008 processing rows without violating restored 0008 CHECK constraint
    op.execute(
        sa.text(
            "UPDATE processing_runs SET status = 'cancelled' "
            "WHERE step_type = 'compare_consistency' "
            "AND status IN ('queued', 'running', 'retry_wait')"
        )
    )
    op.execute(
        sa.text(
            "UPDATE processing_runs SET step_type = 'verify_object_integrity' "
            "WHERE step_type = 'compare_consistency'"
        )
    )

    with op.batch_alter_table("processing_runs", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("fk_processing_runs_org_case", type_="foreignkey")
        batch_op.drop_constraint("ck_processing_runs_step_type_valid", type_="check")
        batch_op.create_check_constraint("ck_processing_runs_step_type_valid", _OLD_STEP_TYPE_SQL)
        batch_op.drop_column("case_id")
