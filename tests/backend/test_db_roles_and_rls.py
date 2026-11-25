"""Tests for security_auth_events triggers, PostgreSQL role separation, and real RLS enforcement."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from app.core.constants import (
    CaseReadinessState,
    MembershipStatus,
    OrganizationRole,
    SecurityAuditOutcome,
)
from app.db.session import (
    apply_pg_identity_context,
    apply_pg_rls_context,
    clear_pg_rls_context,
    create_session_factory,
)
from app.repositories.identity import IdentityAndSessionRepository, SecurityAuditRepository
from app.repositories.institutional import AuditEventRepository, CaseAndDocumentRepository, OrganizationRepository
from app.schemas.tenant import TenantContext


def test_security_audit_events_append_only_triggers_block_sql_mutation(migrated_engine) -> None:
    factory = create_session_factory(migrated_engine)
    SecurityAuditRepository.append_event_atomic(
        factory,
        event_type="TEST_LEDGER_INIT",
        outcome=SecurityAuditOutcome.SUCCESS,
        reason_code="initial_event",
        payload_json={"step": 1},
    )
    session = factory()
    try:
        with pytest.raises((OperationalError, IntegrityError, ProgrammingError, Exception)):
            session.execute(text("UPDATE security_auth_events SET reason_code = 'tampered'"))
        session.rollback()

        with pytest.raises((OperationalError, IntegrityError, ProgrammingError, Exception)):
            session.execute(text("DELETE FROM security_auth_events"))
        session.rollback()

        assert SecurityAuditRepository.verify_chain(session)
    finally:
        session.close()


@pytest.mark.skipif(
    not os.environ.get("JYXIA_TEST_APP_DATABASE_URL", "").strip(),
    reason="PostgreSQL runtime role jyxia_app (JYXIA_TEST_APP_DATABASE_URL) required for real PG RLS checks.",
)
def test_postgresql_runtime_role_rls_security_definer_and_truncate_protection(
    migrated_engine, app_engine
) -> None:
    # Seed Org A & Org B via privileged migration owner connection
    owner_factory = create_session_factory(migrated_engine)
    owner_db = owner_factory()
    try:
        org_a = OrganizationRepository.create_organization(owner_db, slug="rls-a", name="RLS Org A")
        org_b = OrganizationRepository.create_organization(owner_db, slug="rls-b", name="RLS Org B")
        user_a = OrganizationRepository.create_user(
            owner_db, email="rls.a@jyxia.local", display_name="RLS User A", mfa_enrolled=True
        )
        user_a2 = OrganizationRepository.create_user(
            owner_db, email="rls.a2@jyxia.local", display_name="RLS User A2", mfa_enrolled=True
        )
        user_b = OrganizationRepository.create_user(
            owner_db, email="rls.b@jyxia.local", display_name="RLS User B", mfa_enrolled=True
        )
        user_susp = OrganizationRepository.create_user(
            owner_db, email="rls.susp@jyxia.local", display_name="RLS User Suspended", mfa_enrolled=True
        )
        OrganizationRepository.assign_membership(
            owner_db,
            TenantContext(organization_id=org_a.id),
            user_id=user_a.id,
            role=OrganizationRole.ORG_ADMIN.value,
        )
        # User A also holds an active membership in Org B to test Teste 8 (organization switch spoofing)
        OrganizationRepository.assign_membership(
            owner_db,
            TenantContext(organization_id=org_b.id),
            user_id=user_a.id,
            role=OrganizationRole.READ_ONLY.value,
        )
        OrganizationRepository.assign_membership(
            owner_db,
            TenantContext(organization_id=org_a.id),
            user_id=user_a2.id,
            role=OrganizationRole.DOCUMENT_REVIEWER.value,
        )
        OrganizationRepository.assign_membership(
            owner_db,
            TenantContext(organization_id=org_b.id),
            user_id=user_b.id,
            role=OrganizationRole.ORG_ADMIN.value,
        )
        m_susp = OrganizationRepository.assign_membership(
            owner_db,
            TenantContext(organization_id=org_a.id),
            user_id=user_susp.id,
            role=OrganizationRole.READ_ONLY.value,
        )
        m_susp.status = MembershipStatus.SUSPENDED.value

        now_utc = datetime.now(timezone.utc)
        ext_a = IdentityAndSessionRepository.bind_external_identity(
            owner_db,
            user_id=user_a.id,
            issuer="https://idp.jyxia.local/realms/rls",
            subject="sub-rls-a",
            email_at_binding=user_a.email,
        )
        ext_a2 = IdentityAndSessionRepository.bind_external_identity(
            owner_db,
            user_id=user_a2.id,
            issuer="https://idp.jyxia.local/realms/rls",
            subject="sub-rls-a2",
            email_at_binding=user_a2.email,
        )
        ext_b = IdentityAndSessionRepository.bind_external_identity(
            owner_db,
            user_id=user_b.id,
            issuer="https://idp.jyxia.local/realms/rls",
            subject="sub-rls-b",
            email_at_binding=user_b.email,
        )
        ext_susp = IdentityAndSessionRepository.bind_external_identity(
            owner_db,
            user_id=user_susp.id,
            issuer="https://idp.jyxia.local/realms/rls",
            subject="sub-rls-susp",
            email_at_binding=user_susp.email,
        )
        sess_a = IdentityAndSessionRepository.create_auth_session(
            owner_db,
            user_id=user_a.id,
            external_identity_id=ext_a.id,
            active_organization_id=org_a.id,
            session_token_hash="a" * 64,
            csrf_token_hash="c" * 64,
            auth_method="oidc_pkce_mfa",
            acr="urn:jyxia:loa:mfa",
            amr_json=["pwd", "otp"],
            mfa_verified_at=now_utc,
            oidc_auth_time=now_utc,
            idle_expires_at=now_utc + timedelta(minutes=30),
            absolute_expires_at=now_utc + timedelta(hours=8),
            now=now_utc,
        )
        IdentityAndSessionRepository.create_auth_session(
            owner_db,
            user_id=user_a2.id,
            external_identity_id=ext_a2.id,
            active_organization_id=org_a.id,
            session_token_hash="2" * 64,
            csrf_token_hash="e" * 64,
            auth_method="oidc_pkce_mfa",
            acr="urn:jyxia:loa:mfa",
            amr_json=["pwd", "otp"],
            mfa_verified_at=now_utc,
            oidc_auth_time=now_utc,
            idle_expires_at=now_utc + timedelta(minutes=30),
            absolute_expires_at=now_utc + timedelta(hours=8),
            now=now_utc,
        )
        IdentityAndSessionRepository.create_auth_session(
            owner_db,
            user_id=user_b.id,
            external_identity_id=ext_b.id,
            active_organization_id=org_b.id,
            session_token_hash="b" * 64,
            csrf_token_hash="d" * 64,
            auth_method="oidc_pkce_mfa",
            acr="urn:jyxia:loa:mfa",
            amr_json=["pwd", "otp"],
            mfa_verified_at=now_utc,
            oidc_auth_time=now_utc,
            idle_expires_at=now_utc + timedelta(minutes=30),
            absolute_expires_at=now_utc + timedelta(hours=8),
            now=now_utc,
        )
        # Revoked session for User A (Teste 7 & Bloco B)
        sess_revoked = IdentityAndSessionRepository.create_auth_session(
            owner_db,
            user_id=user_a.id,
            external_identity_id=ext_a.id,
            active_organization_id=org_a.id,
            session_token_hash="9" * 64,
            csrf_token_hash="9" * 64,
            auth_method="oidc_pkce_mfa",
            acr="urn:jyxia:loa:mfa",
            amr_json=["pwd", "otp"],
            mfa_verified_at=now_utc,
            oidc_auth_time=now_utc,
            idle_expires_at=now_utc + timedelta(minutes=30),
            absolute_expires_at=now_utc + timedelta(hours=8),
            now=now_utc,
        )
        sess_revoked.revoked_at = now_utc
        sess_revoked.revocation_reason = "revoked_for_test"

        # Expired session for User A (Teste 6 & Bloco B)
        IdentityAndSessionRepository.create_auth_session(
            owner_db,
            user_id=user_a.id,
            external_identity_id=ext_a.id,
            active_organization_id=org_a.id,
            session_token_hash="8" * 64,
            csrf_token_hash="8" * 64,
            auth_method="oidc_pkce_mfa",
            acr="urn:jyxia:loa:mfa",
            amr_json=["pwd", "otp"],
            mfa_verified_at=now_utc - timedelta(minutes=40),
            oidc_auth_time=now_utc - timedelta(minutes=40),
            idle_expires_at=now_utc - timedelta(minutes=5),
            absolute_expires_at=now_utc + timedelta(hours=4),
            now=now_utc - timedelta(minutes=40),
        )
        # Active session for User with SUSPENDED membership in Org A (Teste 9)
        sess_susp = IdentityAndSessionRepository.create_auth_session(
            owner_db,
            user_id=user_susp.id,
            external_identity_id=ext_susp.id,
            active_organization_id=org_a.id,
            session_token_hash="7" * 64,
            csrf_token_hash="7" * 64,
            auth_method="oidc_pkce_mfa",
            acr="urn:jyxia:loa:mfa",
            amr_json=["pwd", "otp"],
            mfa_verified_at=now_utc,
            oidc_auth_time=now_utc,
            idle_expires_at=now_utc + timedelta(minutes=30),
            absolute_expires_at=now_utc + timedelta(hours=8),
            now=now_utc,
        )

        # Active, consumed, and expired OIDC auth states (Bloco B)
        IdentityAndSessionRepository.create_oidc_auth_state(
            owner_db,
            state_hash="1" * 64,
            nonce_hash="2" * 64,
            code_verifier_ciphertext="cipher_rls_state_a_00000000",
            issuer="https://idp.jyxia.local/realms/rls",
            redirect_uri="http://127.0.0.1:8000/api/v1/auth/callback",
            next_path="/",
            expires_at=now_utc + timedelta(minutes=10),
        )
        state_consumed = IdentityAndSessionRepository.create_oidc_auth_state(
            owner_db,
            state_hash="3" * 64,
            nonce_hash="4" * 64,
            code_verifier_ciphertext="cipher_rls_state_b_00000000",
            issuer="https://idp.jyxia.local/realms/rls",
            redirect_uri="http://127.0.0.1:8000/api/v1/auth/callback",
            next_path="/",
            expires_at=now_utc + timedelta(minutes=10),
        )
        state_consumed.consumed_at = now_utc
        IdentityAndSessionRepository.create_oidc_auth_state(
            owner_db,
            state_hash="5" * 64,
            nonce_hash="6" * 64,
            code_verifier_ciphertext="cipher_rls_state_expired_0000",
            issuer="https://idp.jyxia.local/realms/rls",
            redirect_uri="http://127.0.0.1:8000/api/v1/auth/callback",
            next_path="/",
            expires_at=now_utc - timedelta(minutes=5),
        )

        case_a = CaseAndDocumentRepository.create_case(
            owner_db,
            TenantContext(organization_id=org_a.id),
            case_code="RLS-A-1",
            external_reference=None,
            procedure_reference=None,
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        case_b = CaseAndDocumentRepository.create_case(
            owner_db,
            TenantContext(organization_id=org_b.id),
            case_code="RLS-B-1",
            external_reference=None,
            procedure_reference=None,
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        seed_ev_a = AuditEventRepository.append_event(
            owner_db,
            TenantContext(organization_id=org_a.id, actor_user_id=user_a.id),
            event_type="RLS_SEED_A",
            target_entity_type="organization",
            target_entity_id=org_a.id,
            payload_json={"seed": True},
        )
        AuditEventRepository.append_event(
            owner_db,
            TenantContext(organization_id=org_b.id, actor_user_id=user_b.id),
            event_type="RLS_SEED_B",
            target_entity_type="organization",
            target_entity_id=org_b.id,
            payload_json={"seed": True},
        )
        owner_db.commit()
        org_a_id = str(org_a.id)
        org_b_id = str(org_b.id)
        user_a_id = str(user_a.id)
        user_a2_id = str(user_a2.id)
        user_b_id = str(user_b.id)
        user_susp_id = str(user_susp.id)
        ext_b_id = str(ext_b.id)
        sess_a_id = str(sess_a.id)
        sess_susp_id = str(sess_susp.id)
        case_a_id = str(case_a.id)
        case_b_id = str(case_b.id)
        seed_ev_a_hash = str(seed_ev_a.event_hash)

        # Verify BEFORE TRUNCATE trigger blocks even migration owner when trigger is enabled
        with pytest.raises(Exception):
            owner_db.execute(text("TRUNCATE TABLE audit_events"))
        owner_db.rollback()
        with pytest.raises(Exception):
            owner_db.execute(text("TRUNCATE TABLE security_auth_events"))
        owner_db.rollback()
    finally:
        owner_db.close()

    # Now connect STRICTLY as least-privilege runtime role `jyxia_app`
    app_factory = create_session_factory(app_engine)
    app_db = app_factory()
    try:
        role_row = app_db.execute(
            text(
                "SELECT current_user, rolsuper, rolcreatedb, rolcreaterole, rolbypassrls "
                "FROM pg_roles WHERE rolname = current_user"
            )
        ).first()
        assert role_row is not None
        assert role_row[0] == "jyxia_app"
        assert role_row[1] is False  # NOSUPERUSER
        assert role_row[2] is False  # NOCREATEDB
        assert role_row[3] is False  # NOCREATEROLE
        assert role_row[4] is False  # NOBYPASSRLS

        # 0. Verify ENABLE ROW LEVEL SECURITY and FORCE ROW LEVEL SECURITY in pg_class
        force_rls_tables = (
            "organization_memberships",
            "document_cases",
            "documents",
            "document_versions",
            "processing_runs",
            "extracted_fields",
            "evidence_references",
            "human_reviews",
            "consistency_assessments",
            "consistency_axis_results",
            "consistency_axis_evidences",
            "human_reviews",
            "audit_events",
            "external_identities",
            "oidc_auth_states",
            "auth_sessions",
        )
        for tbl in force_rls_tables:
            rls_flags = app_db.execute(
                text("SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = :t"),
                {"t": tbl},
            ).first()
            assert rls_flags == (True, True), f"Expected ENABLE + FORCE RLS on {tbl}, got {rls_flags}"

        # 1. Without context, runtime role MUST see 0 tenant rows and 0 session/identity/state rows
        clear_pg_rls_context(app_db)
        for protected_tbl in (
            "document_cases",
            "audit_events",
            "organization_memberships",
            "auth_sessions",
            "external_identities",
            "oidc_auth_states",
            "security_auth_events",
        ):
            assert app_db.execute(text(f"SELECT count(*) FROM {protected_tbl}")).scalar() == 0

        # 2. Bloco B (ACH-09): Setting ONLY app.current_user_id and app.current_organization_id
        #    (even for User A or fabricated User B / User A2) MUST NOT expose auth_sessions or external_identities!
        for forged_org, forged_user in (
            (org_a_id, user_a_id),
            (org_a_id, user_a2_id),
            (org_b_id, user_b_id),
        ):
            clear_pg_rls_context(app_db)
            apply_pg_rls_context(app_db, organization_id=forged_org, user_id=forged_user)
            assert app_db.execute(text("SELECT count(*) FROM auth_sessions")).scalar() == 0
            assert app_db.execute(text("SELECT count(*) FROM external_identities")).scalar() == 0
            assert (
                app_db.execute(
                    text("UPDATE auth_sessions SET revocation_reason = 'guc-spoof'")
                ).rowcount
                == 0
            )
            assert (
                app_db.execute(
                    text("UPDATE external_identities SET updated_at = now()")
                ).rowcount
                == 0
            )

        # Random, revoked, or expired session_token_hash MUST see 0 auth_sessions and 0 external_identities
        for bad_sess_hash in ("f" * 64, "9" * 64, "8" * 64):
            clear_pg_rls_context(app_db)
            apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
            apply_pg_identity_context(app_db, session_token_hash=bad_sess_hash)
            assert app_db.execute(text("SELECT count(*) FROM auth_sessions")).scalar() == 0
            assert app_db.execute(text("SELECT count(*) FROM external_identities")).scalar() == 0
            assert (
                app_db.execute(
                    text("UPDATE auth_sessions SET last_seen_at = now() WHERE session_token_hash = :h"),
                    {"h": bad_sess_hash},
                ).rowcount
                == 0
            )

        # Unknown, consumed, or expired OIDC state_hash MUST see 0 oidc_auth_states and cannot be updated
        for bad_state_hash in ("f" * 64, "3" * 64, "5" * 64):
            clear_pg_rls_context(app_db)
            apply_pg_identity_context(app_db, oidc_state_hash=bad_state_hash)
            assert app_db.execute(text("SELECT count(*) FROM oidc_auth_states")).scalar() == 0
            assert (
                app_db.execute(
                    text("UPDATE oidc_auth_states SET consumed_at = now() WHERE state_hash = :h"),
                    {"h": bad_state_hash},
                ).rowcount
                == 0
            )

        # Attempting to forge an INSERT into auth_sessions for another user (User B) as jyxia_app MUST fail
        clear_pg_rls_context(app_db)
        apply_pg_rls_context(app_db, organization_id=org_b_id, user_id=user_b_id)
        apply_pg_identity_context(app_db, session_token_hash="f" * 64)
        with pytest.raises(Exception):
            app_db.execute(
                text(
                    "INSERT INTO auth_sessions "
                    "(id, user_id, external_identity_id, active_organization_id, session_token_hash, csrf_token_hash, "
                    "auth_method, acr, amr_json, mfa_verified_at, oidc_auth_time, idle_expires_at, absolute_expires_at, "
                    "last_seen_at, created_at) "
                    "VALUES ('forged-sess', :ub, :ext_b, :org_b, repeat('f', 64), repeat('f', 64), "
                    "'oidc_pkce_mfa', 'urn:jyxia:loa:mfa', '[\"pwd\",\"otp\"]'::jsonb, now(), now(), "
                    "now() + interval '30 minutes', now() + interval '8 hours', now(), now())"
                ),
                {"ub": user_b_id, "ext_b": ext_b_id, "org_b": org_b_id},
            )
        app_db.rollback()

        # With valid active session_token_hash ("a" * 64) + active OIDC state_hash ("1" * 64),
        # runtime sees ONLY User A's active session, ONLY User A's external identity, and ONLY state "1"*64
        # even if app.current_user_id is maliciously pointed to User B!
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_b_id)
        apply_pg_identity_context(
            app_db,
            session_token_hash="a" * 64,
            oidc_state_hash="1" * 64,
        )
        visible_cases = app_db.execute(text("SELECT case_code FROM document_cases")).scalars().all()
        assert visible_cases == ["RLS-A-1"]
        visible_audits = app_db.execute(text("SELECT event_type FROM audit_events")).scalars().all()
        assert visible_audits == ["RLS_SEED_A"]
        visible_sessions = app_db.execute(text("SELECT id, user_id FROM auth_sessions")).all()
        assert visible_sessions == [(sess_a_id, user_a_id)]
        assert (
            app_db.execute(
                text("SELECT count(*) FROM auth_sessions WHERE user_id = :ub"), {"ub": user_b_id}
            ).scalar()
            == 0
        )
        visible_identities = app_db.execute(text("SELECT subject FROM external_identities")).scalars().all()
        assert visible_identities == ["sub-rls-a"]
        assert (
            app_db.execute(
                text("SELECT count(*) FROM external_identities WHERE user_id = :ub"), {"ub": user_b_id}
            ).scalar()
            == 0
        )
        visible_states = app_db.execute(text("SELECT state_hash FROM oidc_auth_states")).scalars().all()
        assert visible_states == ["1" * 64]
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)

        # 3. Cross-tenant INSERT, UPDATE, and DELETE protections under RLS
        with pytest.raises(Exception):
            app_db.execute(
                text(
                    "INSERT INTO document_cases "
                    "(id, organization_id, case_code, readiness_state, administrative_only, clinical_approval, created_at, updated_at) "
                    "VALUES ('bad-rls-id', :org_b, 'ROGUE-B', 'pendente', TRUE, FALSE, now(), now())"
                ),
                {"org_b": org_b_id},
            )
        app_db.rollback()

        # Re-bind Org A context after rollback and verify cross-tenant UPDATE & DELETE fail closed
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
        upd_b_res = app_db.execute(
            text("UPDATE document_cases SET case_code = 'TAMPERED-B' WHERE id = :cb"),
            {"cb": case_b_id},
        )
        assert upd_b_res.rowcount == 0
        with pytest.raises(Exception):
            app_db.execute(
                text("UPDATE document_cases SET organization_id = :org_b WHERE id = :ca"),
                {"org_b": org_b_id, "ca": case_a_id},
            )
        app_db.rollback()

        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
        with pytest.raises(Exception):
            app_db.execute(text("DELETE FROM document_cases WHERE id = :cb"), {"cb": case_b_id})
        app_db.rollback()
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
        with pytest.raises(Exception):
            app_db.execute(text("DELETE FROM document_cases WHERE id = :ca"), {"ca": case_a_id})
        app_db.rollback()

        # 4. Physical connection reuse across Tenant A -> No Context -> Tenant B (zero context leakage)
        pid_tx1 = app_db.execute(text("SELECT pg_backend_pid()")).scalar()
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
        assert app_db.execute(text("SELECT case_code FROM document_cases")).scalars().all() == ["RLS-A-1"]
        app_db.commit()

        pid_tx2 = app_db.execute(text("SELECT pg_backend_pid()")).scalar()
        assert pid_tx2 == pid_tx1
        assert app_db.execute(text("SELECT count(*) FROM document_cases")).scalar() == 0
        assert app_db.execute(text("SELECT count(*) FROM auth_sessions")).scalar() == 0
        assert app_db.execute(text("SELECT count(*) FROM external_identities")).scalar() == 0
        app_db.rollback()

        pid_tx3 = app_db.execute(text("SELECT pg_backend_pid()")).scalar()
        assert pid_tx3 == pid_tx1
        apply_pg_rls_context(app_db, organization_id=org_b_id, user_id=user_b_id)
        apply_pg_identity_context(app_db, session_token_hash="b" * 64)
        assert app_db.execute(text("SELECT case_code FROM document_cases")).scalars().all() == ["RLS-B-1"]
        assert app_db.execute(text("SELECT user_id FROM auth_sessions")).scalars().all() == [user_b_id]
        assert app_db.execute(text("SELECT subject FROM external_identities")).scalars().all() == ["sub-rls-b"]
        app_db.commit()

        # 5. Runtime CANNOT run DDL, direct INSERT/UPDATE/DELETE/TRUNCATE on audit tables, or disable triggers/RLS
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
        for forbidden_sql in (
            "CREATE TABLE rogue_table (id int)",
            "INSERT INTO audit_events (id, organization_id, schema_version, sequence_number, event_type, target_entity_type, target_entity_id, payload_json, prev_event_hash, event_hash, created_at) VALUES ('x', :org_a, 'jyxia.audit.v1', 99, 'X', 'org', 'x', '{}'::jsonb, repeat('0', 64), repeat('1', 64), now())",
            "DELETE FROM audit_events",
            "TRUNCATE TABLE audit_events",
            "DELETE FROM security_auth_events",
            "ALTER TABLE audit_events DISABLE TRIGGER ALL",
            "ALTER TABLE document_cases DISABLE ROW LEVEL SECURITY",
            "SET ROLE jyxia",
        ):
            with pytest.raises(Exception):
                app_db.execute(text(forbidden_sql), {"org_a": org_a_id})
            app_db.rollback()
            apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)

        # 6. Bloco A (ACH-03): All 11 mandatory SECURITY DEFINER spoofing and session-proof tests as jyxia_app
        def _try_raw_audit_definer(
            *,
            ctx_org: str | None,
            ctx_user: str | None,
            ctx_sess_hash: str | None,
            p_org: str,
            p_actor: str | None,
            p_schema: str = "jyxia.audit.v1",
            p_seq: int = 2,
            p_prev_hash: str = seed_ev_a_hash,
            p_ev_hash: str = "e" * 64,
        ) -> None:
            clear_pg_rls_context(app_db)
            apply_pg_rls_context(app_db, organization_id=ctx_org, user_id=ctx_user)
            if ctx_sess_hash is not None:
                apply_pg_identity_context(app_db, session_token_hash=ctx_sess_hash)
            app_db.execute(
                text(
                    "SELECT public.jyxia_append_audit_event("
                    "'bad-ev-id', :p_org, :p_schema, :p_seq, :p_actor, 'FORGED_EVENT', "
                    "'organization', :p_org, '{\"ok\":true}', :p_prev, :p_hash, now())"
                ),
                {
                    "p_org": p_org,
                    "p_schema": p_schema,
                    "p_seq": p_seq,
                    "p_actor": p_actor,
                    "p_prev": p_prev_hash,
                    "p_hash": p_ev_hash,
                },
            )

        def _try_raw_security_definer(
            *,
            ctx_org: str | None,
            ctx_user: str | None,
            ctx_sess_hash: str | None,
            p_org: str | None,
            p_user: str | None,
            p_session_id: str | None = sess_a_id,
            p_event_type: str = "FORGED_SEC",
        ) -> None:
            clear_pg_rls_context(app_db)
            apply_pg_rls_context(app_db, organization_id=ctx_org, user_id=ctx_user)
            if ctx_sess_hash is not None:
                apply_pg_identity_context(app_db, session_token_hash=ctx_sess_hash)
            app_db.execute(
                text(
                    "SELECT public.jyxia_append_security_event("
                    "'bad-sec-id', 'jyxia.sec_audit.v1', 1, :p_ev_type, 'denied', "
                    ":p_u, :p_o, NULL, NULL, :p_sid, NULL, 'forged_reason', '{}', "
                    "repeat('0', 64), repeat('a', 64), now())"
                ),
                {"p_ev_type": p_event_type, "p_u": p_user, "p_o": p_org, "p_sid": p_session_id},
            )

        for bad_audit_kwargs in (
            # Teste 2 — Falsificação de usuário (session belongs to User A, GUC & param point to User A2 in same Org A)
            {"ctx_org": org_a_id, "ctx_user": user_a2_id, "ctx_sess_hash": "a" * 64, "p_org": org_a_id, "p_actor": user_a2_id},
            # Teste 3 — Falsificação de organização (session belongs to Org A, GUC or param points to Org B)
            {"ctx_org": org_b_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_b_id, "p_actor": user_a_id},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_b_id, "p_actor": user_a_id},
            # Teste 4 — Sessão arbitrária (random/chosen session hash)
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "f" * 64, "p_org": org_a_id, "p_actor": user_a_id},
            # Teste 5 — Sessão de outra pessoa sem possuir o token (coherent GUCs for User A2 in Org A, missing or wrong session hash)
            {"ctx_org": org_a_id, "ctx_user": user_a2_id, "ctx_sess_hash": None, "p_org": org_a_id, "p_actor": user_a2_id},
            # Teste 6 — Sessão expirada (User A's expired session "8"*64)
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "8" * 64, "p_org": org_a_id, "p_actor": user_a_id},
            # Teste 7 — Sessão revogada (User A's revoked session "9"*64)
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "9" * 64, "p_org": org_a_id, "p_actor": user_a_id},
            # Teste 8 — Troca de organização (User A is active member of Org B too, but session "a"*64 is bound to Org A)
            {"ctx_org": org_b_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_b_id, "p_actor": user_a_id},
            # Teste 9 — Membership suspensa (User Susp has active session "7"*64 in Org A, but membership in Org A is 'suspended')
            {"ctx_org": org_a_id, "ctx_user": user_susp_id, "ctx_sess_hash": "7" * 64, "p_org": org_a_id, "p_actor": user_susp_id},
            # Teste 11 — Usuário ativo de outra organização (coherent GUCs & params for User B in Org B, without User B's session token)
            {"ctx_org": org_b_id, "ctx_user": user_b_id, "ctx_sess_hash": None, "p_org": org_b_id, "p_actor": user_b_id},
            {"ctx_org": org_b_id, "ctx_user": user_b_id, "ctx_sess_hash": "a" * 64, "p_org": org_b_id, "p_actor": user_b_id},
            # Missing org/user contexts or manipulated schema/sequence/hash
            {"ctx_org": None, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_a_id, "p_actor": user_a_id},
            {"ctx_org": org_a_id, "ctx_user": None, "ctx_sess_hash": "a" * 64, "p_org": org_a_id, "p_actor": user_a_id},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_a_id, "p_actor": None},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_a_id, "p_actor": user_a_id, "p_schema": "bad.v0"},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_a_id, "p_actor": user_a_id, "p_seq": 99},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_a_id, "p_actor": user_a_id, "p_prev_hash": "f" * 64},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_a_id, "p_actor": user_a_id, "p_ev_hash": "NOT_HEX"},
        ):
            with pytest.raises(Exception):
                _try_raw_audit_definer(**bad_audit_kwargs)
            app_db.rollback()

        for bad_sec_kwargs in (
            # Teste 2 — Falsificação de usuário
            {"ctx_org": org_a_id, "ctx_user": user_a2_id, "ctx_sess_hash": "a" * 64, "p_org": org_a_id, "p_user": user_a2_id},
            # Teste 3 — Falsificação de organização
            {"ctx_org": org_b_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_b_id, "p_user": user_a_id},
            # Teste 4 — Sessão arbitrária
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "f" * 64, "p_org": org_a_id, "p_user": user_a_id},
            # Teste 5 — Sessão de outra pessoa (coherent GUCs for User A2 without User A2's session token)
            {"ctx_org": org_a_id, "ctx_user": user_a2_id, "ctx_sess_hash": None, "p_org": org_a_id, "p_user": user_a2_id},
            # Teste 6 — Sessão expirada
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "8" * 64, "p_org": org_a_id, "p_user": user_a_id},
            # Teste 7 — Sessão revogada
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "ctx_sess_hash": "9" * 64, "p_org": org_a_id, "p_user": user_a_id},
            # Teste 8 — Troca de organização
            {"ctx_org": org_b_id, "ctx_user": user_a_id, "ctx_sess_hash": "a" * 64, "p_org": org_b_id, "p_user": user_a_id},
            # Teste 9 — Membership suspensa (even with User Susp's active session "7"*64)
            {"ctx_org": org_a_id, "ctx_user": user_susp_id, "ctx_sess_hash": "7" * 64, "p_org": org_a_id, "p_user": user_susp_id, "p_session_id": sess_susp_id},
            # Teste 10 — Função de evento global (NULL org and NULL user as jyxia_app without authorized OIDC state)
            {"ctx_org": None, "ctx_user": None, "ctx_sess_hash": None, "p_org": None, "p_user": None, "p_session_id": None},
            # Teste 11 — Usuário ativo de outra organização (coherent GUCs for User B in Org B without User B's session token)
            {"ctx_org": org_b_id, "ctx_user": user_b_id, "ctx_sess_hash": None, "p_org": org_b_id, "p_user": user_b_id},
            {"ctx_org": org_b_id, "ctx_user": user_b_id, "ctx_sess_hash": "a" * 64, "p_org": org_b_id, "p_user": user_b_id},
        ):
            with pytest.raises(Exception):
                _try_raw_security_definer(**bad_sec_kwargs)
            app_db.rollback()

        # 7. Teste 1 — Sessão legítima: Runtime CAN append valid events via SECURITY DEFINER when authenticated session & active membership match
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
        apply_pg_identity_context(app_db, session_token_hash="a" * 64)
        appended = AuditEventRepository.append_event(
            app_db,
            TenantContext(
                organization_id=org_a_id,
                actor_user_id=user_a_id,
                session_token_hash="a" * 64,
            ),
            event_type="RUNTIME_SECURITY_DEFINER_OK",
            target_entity_type="organization",
            target_entity_id=org_a_id,
            payload_json={"via": "jyxia_append_audit_event"},
        )
        assert appended.sequence_number == 2
        sec_ev = SecurityAuditRepository.append_event(
            app_db,
            event_type="RUNTIME_SECURITY_LEDGER_OK",
            outcome=SecurityAuditOutcome.SUCCESS,
            reason_code="security_definer_verified",
            payload_json={"role": "jyxia_app"},
            organization_id=org_a_id,
            user_id=user_a_id,
            session_id=sess_a_id,
            session_token_hash="a" * 64,
        )
        assert sec_ev.sequence_number >= 1
        app_db.commit()

        # 8. Verify consume_oidc_auth_state_atomic, finalize_oidc_auth_state, and revoke_session as jyxia_app
        consumed_state = IdentityAndSessionRepository.consume_oidc_auth_state_atomic(
            app_db, state_hash="1" * 64, now=now_utc
        )
        assert consumed_state is not None
        assert consumed_state.state_hash == "1" * 64
        # Once consumed, direct SELECT by jyxia_app sees 0 rows and replay returns None
        assert app_db.execute(text("SELECT count(*) FROM oidc_auth_states")).scalar() == 0
        assert (
            IdentityAndSessionRepository.consume_oidc_auth_state_atomic(
                app_db, state_hash="1" * 64, now=now_utc
            )
            is None
        )
        IdentityAndSessionRepository.finalize_oidc_auth_state(
            app_db, state_hash="1" * 64, now=now_utc
        )
        app_db.commit()

        # 9. Etapa 3.3.1: Verify document ingestion, version immutability trigger, RLS isolation,
        #    and concurrent idempotency on real PostgreSQL 16 as jyxia_app
        from concurrent.futures import ThreadPoolExecutor
        from pathlib import Path
        from app.core.constants import DocumentKind
        from app.services.institutional_service import (
            IdempotencyConflictError,
            InstitutionalService,
        )
        from app.services.storage import LocalControlledSyntheticStorage

        pg_storage_root = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "jyxia_pg16_ingest_test"
        pg_storage = LocalControlledSyntheticStorage(pg_storage_root, enabled=True, max_bytes=1024 * 1024)
        valid_pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n%%EOF\n"

        def _concurrent_ingest(worker_idx: int) -> tuple[str, str, bool]:
            w_db = app_factory()
            try:
                w_ctx = TenantContext(
                    organization_id=org_a_id,
                    actor_user_id=user_a_id,
                    session_token_hash="a" * 64,
                    source="authenticated_request",
                )
                res = InstitutionalService.ingest_case_document(
                    w_db,
                    w_ctx,
                    storage=pg_storage,
                    case_id=case_a_id,
                    content=valid_pdf,
                    mime_type="application/pdf",
                    original_filename=f"laudo-pg16-{worker_idx}.pdf",
                    document_kind=DocumentKind.LAUDO,
                    source_label="pg16_concurrent_ingest",
                    idempotency_key="pg16-concurrent-idem-001",
                )
                return res.document.id, res.version.id, res.idempotent_replay
            finally:
                w_db.close()

        with ThreadPoolExecutor(max_workers=2) as pool:
            f1 = pool.submit(_concurrent_ingest, 1)
            f2 = pool.submit(_concurrent_ingest, 2)
            r1 = f1.result()
            r2 = f2.result()

        assert r1[0] == r2[0], "Concurrent uploads with same Idempotency-Key must resolve to single Document"
        assert r1[1] == r2[1], "Concurrent uploads with same Idempotency-Key must resolve to single DocumentVersion"
        assert {r1[2], r2[2]} == {False, True}

        # Reusing same Idempotency-Key with different PDF payload on PG16 MUST raise IdempotencyConflictError
        with pytest.raises(IdempotencyConflictError):
            InstitutionalService.ingest_case_document(
                app_db,
                TenantContext(
                    organization_id=org_a_id,
                    actor_user_id=user_a_id,
                    session_token_hash="a" * 64,
                    source="authenticated_request",
                ),
                storage=pg_storage,
                case_id=case_a_id,
                content=b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF\n",
                mime_type="application/pdf",
                original_filename="laudo-conflict.pdf",
                document_kind=DocumentKind.LAUDO,
                source_label="pg16_concurrent_ingest",
                idempotency_key="pg16-concurrent-idem-001",
            )
        app_db.rollback()

        # PostgreSQL trigger trg_document_versions_immutable_core MUST block direct SQL mutation of sha256_hex / storage_key / DELETE
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
        apply_pg_identity_context(app_db, session_token_hash="a" * 64)
        with pytest.raises(Exception):
            app_db.execute(
                text("UPDATE document_versions SET sha256_hex = repeat('f', 64) WHERE id = :vid"),
                {"vid": r1[1]},
            )
        app_db.rollback()

        # Tenant B (Org B session "b" * 64) CANNOT see or retrieve Tenant A's ingested document or version under PG16 RLS
        clear_pg_rls_context(app_db)
        apply_pg_rls_context(app_db, organization_id=org_b_id, user_id=user_b_id)
        apply_pg_identity_context(app_db, session_token_hash="b" * 64)
        assert (
            app_db.execute(
                text("SELECT count(*) FROM documents WHERE id = :did"), {"did": r1[0]}
            ).scalar()
            == 0
        )
        assert (
            app_db.execute(
                text("SELECT count(*) FROM document_versions WHERE id = :vid"), {"vid": r1[1]}
            ).scalar()
            == 0
        )
        app_db.rollback()

        # Verify PG16 RLS on human_reviews: Org A can record & read its review; Org B cannot see or mutate it
        from app.core.constants import HumanReviewAction

        ctx_rls_a = TenantContext(
            organization_id=org_a_id,
            actor_user_id=user_a_id,
            session_token_hash="a" * 64,
        )
        rev_res = InstitutionalService.record_document_version_human_review(
            app_db,
            ctx_rls_a,
            document_id=r1[0],
            version_id=r1[1],
            action_type=HumanReviewAction.OBSERVED,
            justification="Conferencia administrativa PG16 RLS verificada.",
            enqueue_comparison=False,
        )
        assert rev_res.review.reviewer_user_id == user_a_id
        assert rev_res.review.organization_id == org_a_id

        clear_pg_rls_context(app_db)
        apply_pg_rls_context(app_db, organization_id=org_b_id, user_id=user_b_id)
        apply_pg_identity_context(app_db, session_token_hash="b" * 64)
        assert (
            app_db.execute(
                text("SELECT count(*) FROM human_reviews WHERE id = :rid"),
                {"rid": rev_res.review.id},
            ).scalar()
            == 0
        )
        app_db.rollback()

        # Verify jyxia_app can revoke its own authenticated session via revoke_session, after which SELECT returns 0 rows
        IdentityAndSessionRepository.revoke_session(
            app_db,
            session_id=sess_a_id,
            now=now_utc,
            reason="rls_self_revocation_test",
            session_token_hash="a" * 64,
        )
        app_db.commit()
        apply_pg_identity_context(app_db, session_token_hash="a" * 64)
        assert app_db.execute(text("SELECT count(*) FROM auth_sessions")).scalar() == 0
        app_db.rollback()
    finally:
        app_db.close()

    # Final chain integrity verification from owner connection
    verify_db = owner_factory()
    try:
        assert AuditEventRepository.verify_chain(verify_db, TenantContext(organization_id=org_a_id))
        assert SecurityAuditRepository.verify_chain(verify_db)
    finally:
        verify_db.close()


@pytest.mark.skipif(
    not os.environ.get("JYXIA_TEST_APP_DATABASE_URL", "").strip()
    or not os.environ.get("JYXIA_TEST_WORKER_DATABASE_URL", "").strip(),
    reason="PostgreSQL runtime roles jyxia_app and jyxia_worker required for PG16 worker tests.",
)
def test_postgresql_worker_role_privilege_isolation_skip_locked_and_lease_recovery(
    migrated_engine, app_engine, worker_engine
) -> None:
    from concurrent.futures import ThreadPoolExecutor
    from pathlib import Path
    from app.core.config import Settings
    from app.core.constants import DocumentKind, ProcessingStatus
    from app.repositories.institutional import LeaseOwnershipError, ProcessingQueueRepository
    from app.services.institutional_service import InstitutionalService
    from app.services.processing_worker import ProcessingWorker
    from app.services.storage import LocalControlledSyntheticStorage

    owner_factory = create_session_factory(migrated_engine)
    app_factory = create_session_factory(app_engine)
    worker_factory = create_session_factory(worker_engine)

    # 1. Verify jyxia_worker PostgreSQL role flags are strictly least-privilege
    w_check = worker_factory()
    try:
        role_row = w_check.execute(
            text(
                "SELECT rolsuper, rolcreatedb, rolcreaterole, rolbypassrls, rolcanlogin, rolinherit "
                "FROM pg_roles WHERE rolname = 'jyxia_worker'"
            )
        ).first()
        assert role_row is not None
        assert tuple(role_row) == (False, False, False, False, True, False)

        # Direct table access MUST be denied for jyxia_worker across sensitive and domain tables
        for tbl in (
            "organizations",
            "users",
            "auth_sessions",
            "external_identities",
            "oidc_auth_states",
            "document_cases",
            "documents",
            "document_versions",
            "processing_runs",
            "extracted_fields",
            "evidence_references",
            "human_reviews",
            "consistency_assessments",
            "consistency_axis_results",
            "consistency_axis_evidences",
            "audit_events",
            "security_auth_events",
        ):
            with pytest.raises(Exception):
                w_check.execute(text(f"SELECT count(*) FROM {tbl}"))
            w_check.rollback()

        with pytest.raises(Exception):
            w_check.execute(text("DELETE FROM processing_runs"))
        w_check.rollback()
        with pytest.raises(Exception):
            w_check.execute(
                text(
                    "INSERT INTO extracted_fields (id, organization_id, processing_run_id, document_version_id, field_key, status, abstained) "
                    "VALUES ('f1', 'o1', 'r1', 'v1', 'patient', 'extracted', false)"
                )
            )
        w_check.rollback()
    finally:
        w_check.close()

    # 2. Verify jyxia_app CANNOT execute jyxia_worker_* SECURITY DEFINER functions
    app_check = app_factory()
    try:
        with pytest.raises(Exception):
            app_check.execute(text("SELECT * FROM public.jyxia_worker_begin_expired_reclaim()"))
        app_check.rollback()
        with pytest.raises(Exception):
            app_check.execute(
                text(
                    "SELECT * FROM public.jyxia_worker_claim_next_run("
                    "'spoof-worker', repeat('a', 64), 30, 'verify_object_integrity')"
                )
            )
        app_check.rollback()
        with pytest.raises(Exception):
            app_check.execute(
                text(
                    "SELECT * FROM public.jyxia_worker_prepare_completion_context("
                    "'nonexistent', 'spoof-worker', repeat('a', 64))"
                )
            )
        app_check.rollback()
        with pytest.raises(Exception):
            app_check.execute(
                text(
                    "SELECT public.jyxia_worker_complete_extraction_run("
                    "'nonexistent', 'spoof-worker', repeat('a', 64), true, '{}', '[]', "
                    "'aid', 1, 'processing_run.succeeded', '{}', repeat('0', 64), repeat('b', 64), now())"
                )
            )
        app_check.rollback()
        with pytest.raises(Exception):
            app_check.execute(
                text(
                    "SELECT * FROM public.jyxia_worker_prepare_extraction_completion_context("
                    "'nonexistent', 'spoof-worker', repeat('a', 64))"
                )
            )
        app_check.rollback()
        with pytest.raises(Exception):
            app_check.execute(
                text(
                    "SELECT public.jyxia_worker_prepare_case_comparison_context("
                    "'nonexistent', 'spoof-worker', repeat('a', 64))"
                )
            )
        app_check.rollback()
        with pytest.raises(Exception):
            app_check.execute(
                text(
                    "SELECT public.jyxia_worker_complete_comparison_run("
                    "'nonexistent', 'spoof-worker', repeat('a', 64), 'pendente', '{}', '{}', '{}', "
                    "'aid', 1, '{}', repeat('0', 64), repeat('b', 64), now())"
                )
            )
        app_check.rollback()
    finally:
        app_check.close()

    # 3. Seed Org A & Org B actors, cases, and authenticated sessions
    owner_db = owner_factory()
    now_utc = datetime.now(timezone.utc)
    try:
        org_a = OrganizationRepository.create_organization(owner_db, slug="wrk-a", name="Worker Org A")
        org_b = OrganizationRepository.create_organization(owner_db, slug="wrk-b", name="Worker Org B")
        user_a = OrganizationRepository.create_user(
            owner_db, email="wrk.a@jyxia.local", display_name="Worker User A", mfa_enrolled=True
        )
        user_b = OrganizationRepository.create_user(
            owner_db, email="wrk.b@jyxia.local", display_name="Worker User B", mfa_enrolled=True
        )
        OrganizationRepository.assign_membership(
            owner_db,
            TenantContext(organization_id=org_a.id),
            user_id=user_a.id,
            role=OrganizationRole.ORG_ADMIN.value,
        )
        OrganizationRepository.assign_membership(
            owner_db,
            TenantContext(organization_id=org_b.id),
            user_id=user_b.id,
            role=OrganizationRole.ORG_ADMIN.value,
        )
        ext_a = IdentityAndSessionRepository.bind_external_identity(
            owner_db,
            user_id=user_a.id,
            issuer="https://idp.jyxia.local/realms/wrk",
            subject="sub-wrk-a",
            email_at_binding=user_a.email,
        )
        ext_b = IdentityAndSessionRepository.bind_external_identity(
            owner_db,
            user_id=user_b.id,
            issuer="https://idp.jyxia.local/realms/wrk",
            subject="sub-wrk-b",
            email_at_binding=user_b.email,
        )
        IdentityAndSessionRepository.create_auth_session(
            owner_db,
            user_id=user_a.id,
            external_identity_id=ext_a.id,
            active_organization_id=org_a.id,
            session_token_hash="1" * 64,
            csrf_token_hash="3" * 64,
            auth_method="oidc_pkce_mfa",
            acr="urn:jyxia:loa:mfa",
            amr_json=["pwd", "otp"],
            mfa_verified_at=now_utc,
            oidc_auth_time=now_utc,
            idle_expires_at=now_utc + timedelta(minutes=30),
            absolute_expires_at=now_utc + timedelta(hours=8),
            now=now_utc,
        )
        IdentityAndSessionRepository.create_auth_session(
            owner_db,
            user_id=user_b.id,
            external_identity_id=ext_b.id,
            active_organization_id=org_b.id,
            session_token_hash="2" * 64,
            csrf_token_hash="4" * 64,
            auth_method="oidc_pkce_mfa",
            acr="urn:jyxia:loa:mfa",
            amr_json=["pwd", "otp"],
            mfa_verified_at=now_utc,
            oidc_auth_time=now_utc,
            idle_expires_at=now_utc + timedelta(minutes=30),
            absolute_expires_at=now_utc + timedelta(hours=8),
            now=now_utc,
        )
        case_a = CaseAndDocumentRepository.create_case(
            owner_db,
            TenantContext(organization_id=org_a.id, actor_user_id=user_a.id),
            case_code="PG-WRK-A-01",
            external_reference=None,
            procedure_reference="PG16 worker test case A",
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        case_b = CaseAndDocumentRepository.create_case(
            owner_db,
            TenantContext(organization_id=org_b.id, actor_user_id=user_b.id),
            case_code="PG-WRK-B-01",
            external_reference=None,
            procedure_reference="PG16 worker test case B",
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        owner_db.commit()
        org_a_id, org_b_id = org_a.id, org_b.id
        user_a_id, user_b_id = user_a.id, user_b.id
        case_a_id, case_b_id = case_a.id, case_b.id
    finally:
        owner_db.close()

    pg_storage_root = Path(os.environ.get("RUNNER_TEMP", "/tmp")) / "jyxia_pg16_worker_test"
    pg_storage = LocalControlledSyntheticStorage(pg_storage_root, enabled=True, max_bytes=1024 * 1024)
    settings = Settings(env="test", storage_root=pg_storage_root.as_posix())
    ctx_a = TenantContext(
        organization_id=org_a_id,
        actor_user_id=user_a_id,
        session_token_hash="1" * 64,
        source="authenticated_request",
    )
    ctx_b = TenantContext(
        organization_id=org_b_id,
        actor_user_id=user_b_id,
        session_token_hash="2" * 64,
        source="authenticated_request",
    )

    def _build_valid_empty_pdf(label: str) -> bytes:
        note = label.encode("ascii", errors="ignore")
        return (
            b"%PDF-1.4\n% " + note + b"\n"
            b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
            b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
            b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>\nendobj\n"
            b"xref\n0 4\n0000000000 65535 f \n"
            b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n140\n%%EOF\n"
        )

    run_ids_a: list[str] = []
    run_ids_b: list[str] = []
    app_db = app_factory()
    try:
        for i in range(3):
            pdf = _build_valid_empty_pdf(f"orgA-doc-{i}")
            ing = InstitutionalService.ingest_case_document(
                app_db,
                ctx_a,
                storage=pg_storage,
                case_id=case_a_id,
                content=pdf,
                mime_type="application/pdf",
                original_filename=f"org-a-{i}.pdf",
                document_kind=DocumentKind.LAUDO,
                source_label="pg16_worker_test",
            )
            assert ing.initial_processing_run is not None
            run_ids_a.append(ing.initial_processing_run.id)

            pdf_b = _build_valid_empty_pdf(f"orgB-doc-{i}")
            ing_b = InstitutionalService.ingest_case_document(
                app_db,
                ctx_b,
                storage=pg_storage,
                case_id=case_b_id,
                content=pdf_b,
                mime_type="application/pdf",
                original_filename=f"org-b-{i}.pdf",
                document_kind=DocumentKind.LAUDO,
                source_label="pg16_worker_test",
            )
            assert ing_b.initial_processing_run is not None
            run_ids_b.append(ing_b.initial_processing_run.id)
    finally:
        app_db.close()

    # 4. Concurrent FOR UPDATE SKIP LOCKED processing across two PG jyxia_worker consumers (6 integrity + 6 extract + 2 compare)
    w1 = ProcessingWorker(worker_factory, pg_storage, settings, worker_id="pg-worker-1")
    w2 = ProcessingWorker(worker_factory, pg_storage, settings, worker_id="pg-worker-2")
    with ThreadPoolExecutor(max_workers=2) as pool:
        fut1 = pool.submit(w1.process_one_cycle, max_jobs=12)
        fut2 = pool.submit(w2.process_one_cycle, max_jobs=12)
        s1 = fut1.result()
        s2 = fut2.result()

    assert s1.claimed + s2.claimed == 14
    assert s1.succeeded + s2.succeeded == 14
    assert s1.failed == 0 and s2.failed == 0
    assert s1.lease_lost == 0 and s2.lease_lost == 0

    app_verify = app_factory()
    try:
        runs_a, total_a = ProcessingQueueRepository.list_case_runs(
            app_verify, ctx_a, case_id=case_a_id, limit=20
        )
        assert total_a == 7
        integrity_runs_a = [r for r, _, _ in runs_a if r.step_type == "verify_object_integrity"]
        extract_runs_a = [r for r, _, _ in runs_a if r.step_type == "extract_pdf_text"]
        compare_runs_a = [r for r, _, _ in runs_a if r.step_type == "compare_consistency"]
        assert len(integrity_runs_a) == 3
        assert len(extract_runs_a) == 3
        assert len(compare_runs_a) == 1
        assert compare_runs_a[0].status == ProcessingStatus.SUCCEEDED.value
        assert compare_runs_a[0].readiness_state == "abstencao"
        assert compare_runs_a[0].result_json is not None
        assert compare_runs_a[0].result_json["clinical_approval"] is False
        assert compare_runs_a[0].result_json["administrative_only"] is True
        for run_row in integrity_runs_a:
            assert run_row.status == ProcessingStatus.SUCCEEDED.value
            assert run_row.attempt_count == 1
            assert run_row.readable is False
            assert run_row.readiness_state is None
            assert run_row.result_json is not None
            assert run_row.result_json["sha256_verified"] is True
            assert run_row.result_json["clinical_approval"] is False
            assert run_row.result_json["administrative_only"] is True
        for run_row in extract_runs_a:
            assert run_row.status == ProcessingStatus.SUCCEEDED.value
            assert run_row.attempt_count == 1
            assert run_row.readiness_state is None
            assert run_row.result_json is not None
            assert run_row.result_json["outcome"] == "abstained"
            assert run_row.result_json["clinical_approval"] is False
            assert run_row.result_json["administrative_only"] is True

        # FORCE RLS isolates Org A processing_runs from Org B session
        clear_pg_rls_context(app_verify)
        apply_pg_rls_context(app_verify, organization_id=org_b_id, user_id=user_b_id)
        apply_pg_identity_context(app_verify, session_token_hash="2" * 64)
        assert (
            app_verify.execute(
                text("SELECT count(*) FROM processing_runs WHERE organization_id = :oa"),
                {"oa": org_a_id},
            ).scalar()
            == 0
        )
        app_verify.rollback()
    finally:
        app_verify.close()

    # 5. Real PostgreSQL 16 lease expiry, stale-lease fencing, and automatic reclaim
    app_re = app_factory()
    try:
        # Enqueue one fresh upload for lease crash/reclaim test
        crash_ing = InstitutionalService.ingest_case_document(
            app_re,
            ctx_a,
            storage=pg_storage,
            case_id=case_a_id,
            content=_build_valid_empty_pdf("lease-recovery-test"),
            mime_type="application/pdf",
            original_filename="lease-recovery.pdf",
            document_kind=DocumentKind.LAUDO,
            source_label="pg16_lease_test",
        )
        assert crash_ing.initial_processing_run is not None
        crash_run_id = crash_ing.initial_processing_run.id
    finally:
        app_re.close()

    _raw_tok, tok_hash = ProcessingQueueRepository.generate_lease_proof()
    w_claim_sess = worker_factory()
    try:
        claimed_crash = ProcessingQueueRepository.claim_next_run(
            w_claim_sess,
            worker_id="pg-crashed-worker",
            lease_token_hash=tok_hash,
            lease_seconds=30,
        )
        assert claimed_crash is not None
        assert claimed_crash.run_id == crash_run_id
        assert claimed_crash.attempt_count == 1
    finally:
        w_claim_sess.close()

    # Force lease expiration via migration owner under explicit tenant RLS context
    owner_exp = owner_factory()
    try:
        apply_pg_rls_context(owner_exp, organization_id=org_a_id, user_id=user_a_id)
        owner_exp.execute(
            text("UPDATE processing_runs SET lease_expires_at = now() - interval '15 seconds' WHERE id = :rid"),
            {"rid": crash_run_id},
        )
        owner_exp.commit()
    finally:
        owner_exp.close()

    # Stale crashed worker CANNOT complete run after lease expiration
    w_stale_sess = worker_factory()
    try:
        with pytest.raises(LeaseOwnershipError):
            ProcessingQueueRepository.complete_run(
                w_stale_sess,
                run_id=crash_run_id,
                worker_id="pg-crashed-worker",
                lease_token_hash=tok_hash,
                result_json={"sha256_verified": True},
            )
    finally:
        w_stale_sess.close()

    # Healthy worker reclaims expired lease, completes verify_object_integrity (attempt 2),
    # chains extract_pdf_text atomically, and triggers barrier compare_consistency cleanly.
    recovery_worker = ProcessingWorker(
        worker_factory, pg_storage, settings, worker_id="pg-recovery-worker"
    )
    rec_stats = recovery_worker.process_one_cycle(max_jobs=5)
    assert rec_stats.reclaimed_leases == 1
    assert rec_stats.claimed == 3
    assert rec_stats.succeeded == 3

    owner_verify = owner_factory()
    try:
        assert AuditEventRepository.verify_chain(owner_verify, TenantContext(organization_id=org_a_id))
        assert AuditEventRepository.verify_chain(owner_verify, TenantContext(organization_id=org_b_id))
        assessments_a, assess_total_a = ProcessingQueueRepository.list_case_consistency_assessments(
            owner_verify, TenantContext(organization_id=org_a_id), case_id=case_a_id
        )
        assert assess_total_a == 2
        assert [a.assessment_sequence for a, _ in assessments_a] == [2, 1]
    finally:
        owner_verify.close()
