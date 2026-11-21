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
        ext_b = IdentityAndSessionRepository.bind_external_identity(
            owner_db,
            user_id=user_b.id,
            issuer="https://idp.jyxia.local/realms/rls",
            subject="sub-rls-b",
            email_at_binding=user_b.email,
        )
        IdentityAndSessionRepository.create_auth_session(
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
        IdentityAndSessionRepository.create_oidc_auth_state(
            owner_db,
            state_hash="3" * 64,
            nonce_hash="4" * 64,
            code_verifier_ciphertext="cipher_rls_state_b_00000000",
            issuer="https://idp.jyxia.local/realms/rls",
            redirect_uri="http://127.0.0.1:8000/api/v1/auth/callback",
            next_path="/",
            expires_at=now_utc + timedelta(minutes=10),
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
        user_b_id = str(user_b.id)
        user_susp_id = str(user_susp.id)
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

        # 2. With Org A + User A RLS context, runtime sees ONLY Org A and ONLY User A's session/identity
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
        apply_pg_identity_context(app_db, oidc_state_hash="1" * 64)
        visible_cases = app_db.execute(text("SELECT case_code FROM document_cases")).scalars().all()
        assert visible_cases == ["RLS-A-1"]
        visible_audits = app_db.execute(text("SELECT event_type FROM audit_events")).scalars().all()
        assert visible_audits == ["RLS_SEED_A"]
        visible_sessions = app_db.execute(text("SELECT user_id FROM auth_sessions")).scalars().all()
        assert visible_sessions == [user_a_id]
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

        # 6. SECURITY DEFINER negative checks (ACH-03): reject missing context, wrong org, wrong/null/non-member/inactive actor
        def _try_raw_audit_definer(
            *,
            ctx_org: str | None,
            ctx_user: str | None,
            p_org: str,
            p_actor: str | None,
            p_schema: str = "jyxia.audit.v1",
            p_seq: int = 2,
            p_prev_hash: str = seed_ev_a_hash,
            p_ev_hash: str = "e" * 64,
        ) -> None:
            apply_pg_rls_context(app_db, organization_id=ctx_org, user_id=ctx_user)
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

        for bad_audit_kwargs in (
            # Missing organization context
            {"ctx_org": None, "ctx_user": user_a_id, "p_org": org_a_id, "p_actor": user_a_id},
            # Organization mismatch against active context (trying to write into Org B while in Org A)
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "p_org": org_b_id, "p_actor": user_a_id},
            # Missing user context or NULL actor as jyxia_app
            {"ctx_org": org_a_id, "ctx_user": None, "p_org": org_a_id, "p_actor": user_a_id},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "p_org": org_a_id, "p_actor": None},
            # Actor mismatch against active user context
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "p_org": org_a_id, "p_actor": user_b_id},
            # Actor belongs to Org B and has NO membership in Org A
            {"ctx_org": org_a_id, "ctx_user": user_b_id, "p_org": org_a_id, "p_actor": user_b_id},
            # Actor has SUSPENDED (inactive) membership in Org A
            {"ctx_org": org_a_id, "ctx_user": user_susp_id, "p_org": org_a_id, "p_actor": user_susp_id},
            # Manipulated schema_version, sequence_number, prev_event_hash, event_hash
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "p_org": org_a_id, "p_actor": user_a_id, "p_schema": "bad.v0"},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "p_org": org_a_id, "p_actor": user_a_id, "p_seq": 99},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "p_org": org_a_id, "p_actor": user_a_id, "p_prev_hash": "f" * 64},
            {"ctx_org": org_a_id, "ctx_user": user_a_id, "p_org": org_a_id, "p_actor": user_a_id, "p_ev_hash": "NOT_HEX"},
        ):
            with pytest.raises(Exception):
                _try_raw_audit_definer(**bad_audit_kwargs)
            app_db.rollback()

        # Negative checks on jyxia_append_security_event (mismatched org, mismatched user, non-member user+org)
        for ctx_o, ctx_u, p_o, p_u in (
            (org_a_id, user_a_id, org_b_id, user_a_id),
            (org_a_id, user_a_id, org_a_id, user_b_id),
            (org_a_id, user_b_id, org_a_id, user_b_id),
        ):
            apply_pg_rls_context(app_db, organization_id=ctx_o, user_id=ctx_u)
            with pytest.raises(Exception):
                app_db.execute(
                    text(
                        "SELECT public.jyxia_append_security_event("
                        "'bad-sec-id', 'jyxia.sec_audit.v1', 1, 'FORGED_SEC', 'denied', "
                        ":p_u, :p_o, NULL, NULL, NULL, NULL, 'forged_reason', '{}', "
                        "repeat('0', 64), repeat('a', 64), now())"
                    ),
                    {"p_u": p_u, "p_o": p_o},
                )
            app_db.rollback()

        # 7. Runtime CAN append valid events via SECURITY DEFINER functions when context & active membership match
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=user_a_id)
        appended = AuditEventRepository.append_event(
            app_db,
            TenantContext(organization_id=org_a_id, actor_user_id=user_a_id),
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
        )
        assert sec_ev.sequence_number >= 1
        app_db.commit()
    finally:
        app_db.close()

    # Final chain integrity verification from owner connection
    verify_db = owner_factory()
    try:
        assert AuditEventRepository.verify_chain(verify_db, TenantContext(organization_id=org_a_id))
        assert SecurityAuditRepository.verify_chain(verify_db)
    finally:
        verify_db.close()
