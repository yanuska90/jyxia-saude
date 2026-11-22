"""Require authenticated session proof in SECURITY DEFINER and RLS, and adopt document_reviewer role.

Revision ID: 20261122_0005
Revises: 20261121_0004
Create Date: 2026-11-22 10:10:00+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20261122_0005"
down_revision = "20261121_0004"
branch_labels = None
depends_on = None

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def _upgrade_pg_authenticated_session_definer_and_rls() -> None:
    # 1. Helper SECURITY DEFINER functions for non-enumerable session and OIDC callback verification.
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_is_session_authorized_for_identity(
                p_external_identity_id varchar
            )
            RETURNS boolean
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_curr_hash varchar;
                v_prev_hash varchar;
            BEGIN
                v_curr_hash := NULLIF(current_setting('app.current_session_token_hash', true), '');
                v_prev_hash := NULLIF(current_setting('app.current_prev_session_token_hash', true), '');

                IF v_curr_hash IS NULL AND v_prev_hash IS NULL THEN
                    RETURN FALSE;
                END IF;

                RETURN EXISTS (
                    SELECT 1
                    FROM public.auth_sessions AS s
                    WHERE s.external_identity_id = p_external_identity_id
                      AND s.revoked_at IS NULL
                      AND s.idle_expires_at > now()
                      AND s.absolute_expires_at > now()
                      AND (
                          (v_curr_hash IS NOT NULL AND s.session_token_hash = v_curr_hash)
                          OR (v_prev_hash IS NOT NULL AND s.session_token_hash = v_prev_hash)
                      )
                );
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_is_valid_oidc_callback_lookup(
                p_issuer varchar,
                p_subject varchar
            )
            RETURNS boolean
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_state_hash varchar;
                v_issuer varchar;
                v_subject varchar;
            BEGIN
                v_state_hash := NULLIF(current_setting('app.current_oidc_state_hash', true), '');
                v_issuer := NULLIF(current_setting('app.current_oidc_issuer', true), '');
                v_subject := NULLIF(current_setting('app.current_oidc_subject', true), '');

                IF v_state_hash IS NULL OR v_state_hash !~ '^[0-9a-f]{64}$' THEN
                    RETURN FALSE;
                END IF;

                IF v_issuer IS NULL OR v_subject IS NULL THEN
                    RETURN FALSE;
                END IF;

                IF p_issuer IS NULL OR p_subject IS NULL OR p_issuer <> v_issuer OR p_subject <> v_subject THEN
                    RETURN FALSE;
                END IF;

                RETURN EXISTS (
                    SELECT 1
                    FROM public.oidc_auth_states AS oas
                    WHERE oas.state_hash = v_state_hash
                      AND oas.issuer = v_issuer
                      AND oas.consumed_at IS NOT NULL
                      AND oas.expires_at > now()
                );
            END;
            $$;
            """
        )
    )

    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_finalize_oidc_auth_state(
                p_state_hash varchar
            )
            RETURNS void
            LANGUAGE plpgsql
            SECURITY DEFINER
            SET search_path = pg_catalog, public
            AS $$
            DECLARE
                v_ctx_state varchar;
            BEGIN
                v_ctx_state := NULLIF(current_setting('app.current_oidc_state_hash', true), '');
                IF p_state_hash IS NULL OR v_ctx_state IS NULL OR p_state_hash <> v_ctx_state THEN
                    RAISE EXCEPTION 'OIDC state finalize rejected: state_hash mismatch against active context';
                END IF;

                UPDATE public.oidc_auth_states
                SET expires_at = now()
                WHERE state_hash = p_state_hash
                  AND consumed_at IS NOT NULL
                  AND expires_at > now();
            END;
            $$;
            """
        )
    )

    # 2. Harden jyxia_append_audit_event to require unforgeable active session proof for jyxia_app.
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
                v_ctx_sess_hash varchar;
                v_sess_id varchar;
                v_sess_user_id varchar;
                v_sess_org_id varchar;
                v_sess_revoked_at timestamptz;
                v_sess_idle_exp timestamptz;
                v_sess_abs_exp timestamptz;
                v_sess_mfa_at timestamptz;
                v_identity_status varchar;
                v_org_exists varchar;
                v_actor_active boolean;
                v_membership_status varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                v_ctx_org := NULLIF(current_setting('app.current_organization_id', true), '');
                v_ctx_user := NULLIF(current_setting('app.current_user_id', true), '');
                v_ctx_sess_hash := NULLIF(current_setting('app.current_session_token_hash', true), '');

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

                    IF v_ctx_sess_hash IS NULL OR v_ctx_sess_hash !~ '^[0-9a-f]{64}$' THEN
                        RAISE EXCEPTION 'Audit append rejected: runtime role requires valid authenticated session_token_hash proof';
                    END IF;

                    SELECT
                        s.id,
                        s.user_id,
                        s.active_organization_id,
                        s.revoked_at,
                        s.idle_expires_at,
                        s.absolute_expires_at,
                        s.mfa_verified_at,
                        ei.status
                    INTO
                        v_sess_id,
                        v_sess_user_id,
                        v_sess_org_id,
                        v_sess_revoked_at,
                        v_sess_idle_exp,
                        v_sess_abs_exp,
                        v_sess_mfa_at,
                        v_identity_status
                    FROM public.auth_sessions AS s
                    JOIN public.external_identities AS ei ON ei.id = s.external_identity_id
                    WHERE s.session_token_hash = v_ctx_sess_hash;

                    IF v_sess_id IS NULL THEN
                        RAISE EXCEPTION 'Audit append rejected: session_token_hash does not match any authenticated session';
                    END IF;

                    IF v_sess_revoked_at IS NOT NULL THEN
                        RAISE EXCEPTION 'Audit append rejected: authenticated session has been revoked';
                    END IF;

                    IF v_sess_idle_exp <= now() OR v_sess_abs_exp <= now() THEN
                        RAISE EXCEPTION 'Audit append rejected: authenticated session has expired';
                    END IF;

                    IF v_sess_mfa_at IS NULL THEN
                        RAISE EXCEPTION 'Audit append rejected: authenticated session lacks MFA assurance';
                    END IF;

                    IF v_identity_status <> 'active' THEN
                        RAISE EXCEPTION 'Audit append rejected: federated identity is not active';
                    END IF;

                    IF v_sess_user_id <> p_actor_user_id THEN
                        RAISE EXCEPTION 'Audit append rejected: session owner (%) does not match actor_user_id (%)',
                            v_sess_user_id, p_actor_user_id;
                    END IF;

                    IF v_sess_org_id IS NULL OR v_sess_org_id <> p_organization_id THEN
                        RAISE EXCEPTION 'Audit append rejected: session active_organization_id (%) does not match target organization (%)',
                            COALESCE(v_sess_org_id, '<null>'), p_organization_id;
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

    # 3. Harden jyxia_append_security_event to require authenticated session or OIDC transaction state proof.
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
                v_ctx_sess_hash varchar;
                v_ctx_state_hash varchar;
                v_ctx_issuer varchar;
                v_ctx_subject varchar;
                v_sess_id varchar;
                v_sess_user_id varchar;
                v_sess_org_id varchar;
                v_sess_revoked_at timestamptz;
                v_sess_idle_exp timestamptz;
                v_sess_abs_exp timestamptz;
                v_sess_mfa_at timestamptz;
                v_user_active boolean;
                v_identity_status varchar;
                v_oas_issuer varchar;
                v_oas_consumed_at timestamptz;
                v_oas_expires_at timestamptz;
                v_resolved_user_id varchar;
                v_membership_status varchar;
                v_expected_seq integer;
                v_expected_prev varchar;
            BEGIN
                v_ctx_org := NULLIF(current_setting('app.current_organization_id', true), '');
                v_ctx_user := NULLIF(current_setting('app.current_user_id', true), '');
                v_ctx_sess_hash := NULLIF(current_setting('app.current_session_token_hash', true), '');
                v_ctx_state_hash := NULLIF(current_setting('app.current_oidc_state_hash', true), '');
                v_ctx_issuer := NULLIF(current_setting('app.current_oidc_issuer', true), '');
                v_ctx_subject := NULLIF(current_setting('app.current_oidc_subject', true), '');

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

                IF session_user = 'jyxia_app' THEN
                    IF v_ctx_sess_hash IS NOT NULL THEN
                        IF v_ctx_sess_hash !~ '^[0-9a-f]{64}$' THEN
                            RAISE EXCEPTION 'Security audit append rejected: malformed session_token_hash context';
                        END IF;

                        SELECT
                            s.id,
                            s.user_id,
                            s.active_organization_id,
                            s.revoked_at,
                            s.idle_expires_at,
                            s.absolute_expires_at,
                            s.mfa_verified_at,
                            u.is_active,
                            ei.status
                        INTO
                            v_sess_id,
                            v_sess_user_id,
                            v_sess_org_id,
                            v_sess_revoked_at,
                            v_sess_idle_exp,
                            v_sess_abs_exp,
                            v_sess_mfa_at,
                            v_user_active,
                            v_identity_status
                        FROM public.auth_sessions AS s
                        JOIN public.users AS u ON u.id = s.user_id
                        JOIN public.external_identities AS ei ON ei.id = s.external_identity_id
                        WHERE s.session_token_hash = v_ctx_sess_hash;

                        IF v_sess_id IS NULL THEN
                            RAISE EXCEPTION 'Security audit append rejected: session_token_hash does not match any authenticated session';
                        END IF;

                        IF p_user_id IS NULL OR v_ctx_user IS NULL OR p_user_id <> v_ctx_user OR p_user_id <> v_sess_user_id THEN
                            RAISE EXCEPTION 'Security audit append rejected: user_id does not match authenticated session owner';
                        END IF;

                        IF p_session_id IS NOT NULL AND p_session_id <> v_sess_id THEN
                            RAISE EXCEPTION 'Security audit append rejected: session_id does not match authenticated session';
                        END IF;

                        IF p_event_type IN ('AUTH_SESSION_EXPIRED', 'AUTH_SESSION_IDENTITY_REVOKED') THEN
                            IF v_sess_revoked_at IS NULL OR v_sess_revoked_at <> p_created_at THEN
                                RAISE EXCEPTION 'Security audit append rejected: session invalidation event requires current revocation timestamp';
                            END IF;
                        ELSE
                            IF v_sess_revoked_at IS NOT NULL THEN
                                RAISE EXCEPTION 'Security audit append rejected: authenticated session has been revoked';
                            END IF;

                            IF v_sess_idle_exp <= now() OR v_sess_abs_exp <= now() THEN
                                RAISE EXCEPTION 'Security audit append rejected: authenticated session has expired';
                            END IF;

                            IF v_sess_mfa_at IS NULL THEN
                                RAISE EXCEPTION 'Security audit append rejected: authenticated session lacks MFA assurance';
                            END IF;

                            IF v_user_active IS DISTINCT FROM TRUE OR v_identity_status <> 'active' THEN
                                RAISE EXCEPTION 'Security audit append rejected: session owner user or identity is inactive';
                            END IF;
                        END IF;

                        IF p_organization_id IS NOT NULL THEN
                            IF v_ctx_org IS NULL OR p_organization_id <> v_ctx_org THEN
                                RAISE EXCEPTION 'Security audit append rejected: organization_id (%) does not match active context (%)',
                                    p_organization_id, COALESCE(v_ctx_org, '<null>');
                            END IF;

                            IF v_sess_org_id IS NULL OR p_organization_id <> v_sess_org_id THEN
                                RAISE EXCEPTION 'Security audit append rejected: organization_id (%) does not match session active_organization_id (%)',
                                    p_organization_id, COALESCE(v_sess_org_id, '<null>');
                            END IF;

                            IF NOT EXISTS (
                                SELECT 1
                                FROM public.organizations AS o
                                WHERE o.id = p_organization_id
                                  AND o.status = 'active'
                            ) THEN
                                RAISE EXCEPTION 'Security audit append rejected: active organization % does not exist', p_organization_id;
                            END IF;

                            SELECT om.status INTO v_membership_status
                            FROM public.organization_memberships AS om
                            WHERE om.organization_id = p_organization_id
                              AND om.user_id = p_user_id;

                            IF v_membership_status IS NULL OR v_membership_status <> 'active' THEN
                                RAISE EXCEPTION 'Security audit append rejected: user % lacks active membership in organization %',
                                    p_user_id, p_organization_id;
                            END IF;
                        END IF;
                    ELSIF v_ctx_state_hash IS NOT NULL THEN
                        IF v_ctx_state_hash !~ '^[0-9a-f]{64}$' THEN
                            RAISE EXCEPTION 'Security audit append rejected: malformed oidc_state_hash context';
                        END IF;

                        SELECT oas.issuer, oas.consumed_at, oas.expires_at
                        INTO v_oas_issuer, v_oas_consumed_at, v_oas_expires_at
                        FROM public.oidc_auth_states AS oas
                        WHERE oas.state_hash = v_ctx_state_hash;

                        IF v_oas_issuer IS NULL OR v_oas_expires_at <= now() THEN
                            RAISE EXCEPTION 'Security audit append rejected: oidc_state_hash does not match an active OIDC transaction';
                        END IF;

                        IF p_organization_id IS NOT NULL OR p_session_id IS NOT NULL THEN
                            RAISE EXCEPTION 'Security audit append rejected: pre-session OIDC transaction cannot bind organization_id or session_id';
                        END IF;

                        IF p_issuer IS NULL OR p_issuer <> v_oas_issuer THEN
                            RAISE EXCEPTION 'Security audit append rejected: issuer mismatch against OIDC transaction state';
                        END IF;

                        IF p_event_type NOT IN (
                            'OIDC_LOGIN_STARTED',
                            'OIDC_CALLBACK_FAILED',
                            'OIDC_PROVIDER_UNAVAILABLE',
                            'OIDC_TOKEN_OR_MFA_REJECTED',
                            'AUTH_IDENTITY_UNBOUND',
                            'AUTH_IDENTITY_DISABLED',
                            'AUTH_NO_ACTIVE_MEMBERSHIP'
                        ) THEN
                            RAISE EXCEPTION 'Security audit append rejected: event_type % is not permitted in pre-session OIDC state context', p_event_type;
                        END IF;

                        IF p_event_type IN ('AUTH_IDENTITY_DISABLED', 'AUTH_NO_ACTIVE_MEMBERSHIP') THEN
                            IF v_oas_consumed_at IS NULL OR p_user_id IS NULL OR v_ctx_user IS NULL OR p_user_id <> v_ctx_user THEN
                                RAISE EXCEPTION 'Security audit append rejected: pre-session identity status event requires consumed state and matching user context';
                            END IF;

                            SELECT ei.user_id INTO v_resolved_user_id
                            FROM public.external_identities AS ei
                            WHERE ei.issuer = v_ctx_issuer
                              AND ei.subject = v_ctx_subject;

                            IF v_resolved_user_id IS NULL OR v_resolved_user_id <> p_user_id THEN
                                RAISE EXCEPTION 'Security audit append rejected: user_id does not match verified external identity in callback';
                            END IF;
                        ELSE
                            IF p_user_id IS NOT NULL THEN
                                RAISE EXCEPTION 'Security audit append rejected: pre-identity OIDC event cannot specify user_id';
                            END IF;
                        END IF;
                    ELSE
                        RAISE EXCEPTION 'Security audit append rejected: runtime role cannot append global or user events without authenticated session or OIDC transaction state proof';
                    END IF;
                ELSE
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
                              AND om.status = 'active'
                        ) THEN
                            RAISE EXCEPTION 'Security audit append rejected: user % lacks active membership in organization %',
                                p_user_id, p_organization_id;
                        END IF;
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

    # 4. Replace RLS policies on auth_sessions, external_identities, and oidc_auth_states
    #    eliminating reliance on app.current_user_id or app.current_organization_id.
    op.execute(sa.text("DROP POLICY IF EXISTS p_auth_sessions_isolation ON auth_sessions;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_auth_sessions_select ON auth_sessions;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_auth_sessions_insert ON auth_sessions;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_auth_sessions_update ON auth_sessions;"))

    op.execute(
        sa.text(
            """
            CREATE POLICY p_auth_sessions_select ON auth_sessions
            FOR SELECT
            USING (
                session_user <> 'jyxia_app'
                OR (
                    NULLIF(current_setting('app.current_session_token_hash', true), '') IS NOT NULL
                    AND session_token_hash = NULLIF(current_setting('app.current_session_token_hash', true), '')
                    AND revoked_at IS NULL
                    AND idle_expires_at > now()
                    AND absolute_expires_at > now()
                )
            );
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE POLICY p_auth_sessions_insert ON auth_sessions
            FOR INSERT
            WITH CHECK (
                session_user <> 'jyxia_app'
                OR (
                    NULLIF(current_setting('app.current_session_token_hash', true), '') IS NOT NULL
                    AND session_token_hash = NULLIF(current_setting('app.current_session_token_hash', true), '')
                    AND revoked_at IS NULL
                    AND idle_expires_at > now()
                    AND absolute_expires_at > now()
                    AND EXISTS (
                        SELECT 1
                        FROM public.users AS u
                        WHERE u.id = auth_sessions.user_id
                          AND u.is_active = TRUE
                    )
                    AND EXISTS (
                        SELECT 1
                        FROM public.external_identities AS ei
                        WHERE ei.id = auth_sessions.external_identity_id
                          AND ei.user_id = auth_sessions.user_id
                          AND ei.status = 'active'
                    )
                    AND (
                        auth_sessions.active_organization_id IS NULL
                        OR EXISTS (
                            SELECT 1
                            FROM public.organization_memberships AS om
                            JOIN public.organizations AS o ON o.id = om.organization_id
                            WHERE om.organization_id = auth_sessions.active_organization_id
                              AND om.user_id = auth_sessions.user_id
                              AND om.status = 'active'
                              AND o.status = 'active'
                        )
                    )
                )
            );
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE POLICY p_auth_sessions_update ON auth_sessions
            FOR UPDATE
            USING (
                session_user <> 'jyxia_app'
                OR (
                    NULLIF(current_setting('app.current_session_token_hash', true), '') IS NOT NULL
                    AND session_token_hash = NULLIF(current_setting('app.current_session_token_hash', true), '')
                    AND revoked_at IS NULL
                    AND idle_expires_at > now()
                    AND absolute_expires_at > now()
                )
            )
            WITH CHECK (
                session_user <> 'jyxia_app'
                OR (
                    NULLIF(current_setting('app.current_session_token_hash', true), '') IS NOT NULL
                    AND session_token_hash = NULLIF(current_setting('app.current_session_token_hash', true), '')
                )
            );
            """
        )
    )

    op.execute(sa.text("DROP POLICY IF EXISTS p_external_identities_isolation ON external_identities;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_external_identities_select ON external_identities;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_external_identities_insert ON external_identities;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_external_identities_update ON external_identities;"))

    op.execute(
        sa.text(
            """
            CREATE POLICY p_external_identities_select ON external_identities
            FOR SELECT
            USING (
                session_user <> 'jyxia_app'
                OR public.jyxia_is_session_authorized_for_identity(external_identities.id)
                OR public.jyxia_is_valid_oidc_callback_lookup(external_identities.issuer, external_identities.subject)
            );
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE POLICY p_external_identities_insert ON external_identities
            FOR INSERT
            WITH CHECK (
                session_user <> 'jyxia_app'
            );
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE POLICY p_external_identities_update ON external_identities
            FOR UPDATE
            USING (
                session_user <> 'jyxia_app'
                OR public.jyxia_is_session_authorized_for_identity(external_identities.id)
                OR public.jyxia_is_valid_oidc_callback_lookup(external_identities.issuer, external_identities.subject)
            )
            WITH CHECK (
                session_user <> 'jyxia_app'
                OR public.jyxia_is_session_authorized_for_identity(external_identities.id)
                OR public.jyxia_is_valid_oidc_callback_lookup(external_identities.issuer, external_identities.subject)
            );
            """
        )
    )

    op.execute(sa.text("DROP POLICY IF EXISTS p_oidc_auth_states_isolation ON oidc_auth_states;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_oidc_auth_states_select ON oidc_auth_states;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_oidc_auth_states_insert ON oidc_auth_states;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_oidc_auth_states_update ON oidc_auth_states;"))

    op.execute(
        sa.text(
            """
            CREATE POLICY p_oidc_auth_states_select ON oidc_auth_states
            FOR SELECT
            USING (
                session_user <> 'jyxia_app'
                OR (
                    NULLIF(current_setting('app.current_oidc_state_hash', true), '') IS NOT NULL
                    AND state_hash = NULLIF(current_setting('app.current_oidc_state_hash', true), '')
                    AND consumed_at IS NULL
                    AND expires_at > now()
                )
            );
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE POLICY p_oidc_auth_states_insert ON oidc_auth_states
            FOR INSERT
            WITH CHECK (
                session_user <> 'jyxia_app'
                OR (
                    NULLIF(current_setting('app.current_oidc_state_hash', true), '') IS NOT NULL
                    AND state_hash = NULLIF(current_setting('app.current_oidc_state_hash', true), '')
                    AND consumed_at IS NULL
                    AND expires_at > now()
                )
            );
            """
        )
    )
    op.execute(
        sa.text(
            """
            CREATE POLICY p_oidc_auth_states_update ON oidc_auth_states
            FOR UPDATE
            USING (
                session_user <> 'jyxia_app'
                OR (
                    NULLIF(current_setting('app.current_oidc_state_hash', true), '') IS NOT NULL
                    AND state_hash = NULLIF(current_setting('app.current_oidc_state_hash', true), '')
                    AND consumed_at IS NULL
                    AND expires_at > now()
                )
            )
            WITH CHECK (
                session_user <> 'jyxia_app'
                OR (
                    NULLIF(current_setting('app.current_oidc_state_hash', true), '') IS NOT NULL
                    AND state_hash = NULLIF(current_setting('app.current_oidc_state_hash', true), '')
                    AND consumed_at IS NOT NULL
                    AND expires_at > now()
                )
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
                REVOKE ALL ON FUNCTION public.jyxia_is_session_authorized_for_identity(varchar) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_is_valid_oidc_callback_lookup(varchar, varchar) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_finalize_oidc_auth_state(varchar) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_append_audit_event(
                    varchar, varchar, varchar, integer, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;
                REVOKE ALL ON FUNCTION public.jyxia_append_security_event(
                    varchar, varchar, integer, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, varchar, text, varchar, varchar, timestamptz
                ) FROM PUBLIC;

                IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'jyxia_app') THEN
                    GRANT EXECUTE ON FUNCTION public.jyxia_is_session_authorized_for_identity(varchar) TO jyxia_app;
                    GRANT EXECUTE ON FUNCTION public.jyxia_is_valid_oidc_callback_lookup(varchar, varchar) TO jyxia_app;
                    GRANT EXECUTE ON FUNCTION public.jyxia_finalize_oidc_auth_state(varchar) TO jyxia_app;
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


def _downgrade_pg_authenticated_session_definer_and_rls() -> None:
    op.execute(sa.text("DROP POLICY IF EXISTS p_oidc_auth_states_select ON oidc_auth_states;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_oidc_auth_states_insert ON oidc_auth_states;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_oidc_auth_states_update ON oidc_auth_states;"))
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

    op.execute(sa.text("DROP POLICY IF EXISTS p_external_identities_select ON external_identities;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_external_identities_insert ON external_identities;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_external_identities_update ON external_identities;"))
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

    op.execute(sa.text("DROP POLICY IF EXISTS p_auth_sessions_select ON auth_sessions;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_auth_sessions_insert ON auth_sessions;"))
    op.execute(sa.text("DROP POLICY IF EXISTS p_auth_sessions_update ON auth_sessions;"))
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

    op.execute(sa.text("DROP FUNCTION IF EXISTS public.jyxia_finalize_oidc_auth_state(varchar);"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS public.jyxia_is_valid_oidc_callback_lookup(varchar, varchar);"))
    op.execute(sa.text("DROP FUNCTION IF EXISTS public.jyxia_is_session_authorized_for_identity(varchar);"))

    # Restore 20261121_0004 function definitions
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
    with op.batch_alter_table("organization_memberships", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_organization_memberships_role_valid", type_="check")
        batch_op.create_check_constraint(
            "ck_organization_memberships_role_valid",
            "role IN ('org_admin', 'document_reviewer', 'clinical_reviewer', 'admin_operator', 'auditor_readonly', 'read_only')",
        )
    op.execute(
        sa.text(
            "UPDATE organization_memberships SET role = 'document_reviewer' WHERE role = 'clinical_reviewer'"
        )
    )

    if bind.dialect.name == "postgresql":
        _upgrade_pg_authenticated_session_definer_and_rls()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _downgrade_pg_authenticated_session_definer_and_rls()

    op.execute(
        sa.text(
            "UPDATE organization_memberships SET role = 'clinical_reviewer' WHERE role = 'document_reviewer'"
        )
    )
    with op.batch_alter_table("organization_memberships", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_organization_memberships_role_valid", type_="check")
        batch_op.create_check_constraint(
            "ck_organization_memberships_role_valid",
            "role IN ('org_admin', 'clinical_reviewer', 'admin_operator', 'auditor_readonly', 'read_only')",
        )
