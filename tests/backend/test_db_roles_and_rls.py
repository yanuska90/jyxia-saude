"""Tests for security_auth_events triggers, PostgreSQL role separation, and real RLS enforcement."""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError

from app.core.constants import (
    CaseReadinessState,
    OrganizationRole,
    SecurityAuditOutcome,
)
from app.db.session import apply_pg_rls_context, create_session_factory
from app.repositories.identity import SecurityAuditRepository
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
        OrganizationRepository.assign_membership(
            owner_db,
            TenantContext(organization_id=org_a.id),
            user_id=user_a.id,
            role=OrganizationRole.ORG_ADMIN.value,
        )
        CaseAndDocumentRepository.create_case(
            owner_db,
            TenantContext(organization_id=org_a.id),
            case_code="RLS-A-1",
            external_reference=None,
            procedure_reference=None,
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        CaseAndDocumentRepository.create_case(
            owner_db,
            TenantContext(organization_id=org_b.id),
            case_code="RLS-B-1",
            external_reference=None,
            procedure_reference=None,
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        AuditEventRepository.append_event(
            owner_db,
            TenantContext(organization_id=org_a.id, actor_user_id=user_a.id),
            event_type="RLS_SEED_A",
            target_entity_type="organization",
            target_entity_id=org_a.id,
            payload_json={"seed": True},
        )
        AuditEventRepository.append_event(
            owner_db,
            TenantContext(organization_id=org_b.id),
            event_type="RLS_SEED_B",
            target_entity_type="organization",
            target_entity_id=org_b.id,
            payload_json={"seed": True},
        )
        owner_db.commit()
        org_a_id = str(org_a.id)
        org_b_id = str(org_b.id)
        user_a_id = str(user_a.id)

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

        # 1. Without app.current_organization_id, runtime role MUST see 0 tenant rows
        assert app_db.execute(text("SELECT count(*) FROM document_cases")).scalar() == 0
        assert app_db.execute(text("SELECT count(*) FROM audit_events")).scalar() == 0

        # 2. With Org A RLS context, runtime sees ONLY Org A (0 Org B rows!)
        apply_pg_rls_context(app_db, organization_id=org_a_id, user_id=None)
        visible_cases = app_db.execute(text("SELECT case_code FROM document_cases")).scalars().all()
        assert visible_cases == ["RLS-A-1"]
        visible_audits = app_db.execute(text("SELECT event_type FROM audit_events")).scalars().all()
        assert visible_audits == ["RLS_SEED_A"]

        # 3. Runtime CANNOT insert row targeting Org B while Org A context is active (RLS WITH CHECK!)
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

        # 4. Runtime CANNOT run DDL, direct INSERT/UPDATE/DELETE/TRUNCATE on audit tables, or disable triggers
        for forbidden_sql in (
            "CREATE TABLE rogue_table (id int)",
            "INSERT INTO audit_events (id, organization_id, schema_version, sequence_number, event_type, target_entity_type, target_entity_id, payload_json, prev_event_hash, event_hash, created_at) VALUES ('x', :org_a, 'jyxia.audit.v1', 99, 'X', 'org', 'x', '{}'::jsonb, repeat('0', 64), repeat('1', 64), now())",
            "DELETE FROM audit_events",
            "TRUNCATE TABLE audit_events",
            "DELETE FROM security_auth_events",
            "ALTER TABLE audit_events DISABLE TRIGGER ALL",
        ):
            with pytest.raises(Exception):
                app_db.execute(text(forbidden_sql), {"org_a": org_a_id})
            app_db.rollback()

        # 5. Runtime CAN append via SECURITY DEFINER functions (Audit & SecurityAudit repositories)
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
