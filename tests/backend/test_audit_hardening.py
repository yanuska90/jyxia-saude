"""Tests for audit canonicalization, SQL triggers, tampering detection and concurrency."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session

from app.core.constants import OrganizationRole
from app.db.session import create_session_factory
from app.models.entities import AUDIT_SCHEMA_VERSION, AuditEvent
from app.repositories.institutional import (
    AuditPayloadError,
    compute_audit_event_hash,
    verify_event_sequence,
)
from app.schemas.tenant import (
    MembershipAssignInput,
    OrganizationCreateInput,
    TenantContext,
    UserCreateInput,
)
from app.services.institutional_service import InstitutionalService


@dataclass
class _DetachedEvent:
    organization_id: str
    schema_version: str
    sequence_number: int
    actor_user_id: str | None
    event_type: str
    target_entity_type: str
    target_entity_id: str
    payload_json: dict[str, Any]
    prev_event_hash: str
    event_hash: str
    created_at: datetime


def test_audit_hash_canonicalization_and_payload_safeguards() -> None:
    ts = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
    h1 = compute_audit_event_hash(
        organization_id="org-1",
        sequence_number=1,
        actor_user_id="user-1",
        event_type="case.created",
        target_entity_type="document_case",
        target_entity_id="case-1",
        created_at=ts,
        payload_json={"b": 2, "a": 1},
        prev_event_hash="0" * 64,
    )
    h2 = compute_audit_event_hash(
        organization_id="org-1",
        sequence_number=1,
        actor_user_id="user-1",
        event_type="case.created",
        target_entity_type="document_case",
        target_entity_id="case-1",
        created_at=ts.replace(tzinfo=None),  # SQLite naive UTC equivalence
        payload_json={"a": 1, "b": 2},
        prev_event_hash="0" * 64,
    )
    assert h1 == h2

    # Changing actor or timestamp changes canonical hash
    h_actor = compute_audit_event_hash(
        organization_id="org-1",
        sequence_number=1,
        actor_user_id="user-2",
        event_type="case.created",
        target_entity_type="document_case",
        target_entity_id="case-1",
        created_at=ts,
        payload_json={"a": 1, "b": 2},
        prev_event_hash="0" * 64,
    )
    assert h_actor != h1


def test_audit_direct_sql_update_and_delete_blocked_by_db_triggers(
    db_session: Session, migrated_engine
) -> None:
    org = InstitutionalService.create_organization(
        db_session, OrganizationCreateInput(slug="audit-trigger-org", name="Audit Trigger Org")
    )
    user = InstitutionalService.create_user(
        db_session, UserCreateInput(email="trig@exemplo.invalid", display_name="Trigger Tester")
    )
    ctx = TenantContext(organization_id=org.id)
    InstitutionalService.assign_membership(
        db_session, ctx, MembershipAssignInput(user_id=user.id, role=OrganizationRole.ORG_ADMIN)
    )
    db_session.commit()

    # Forbidden sensitive payloads rejected cleanly
    with pytest.raises(AuditPayloadError):
        InstitutionalService.append_audit_event_atomic(
            create_session_factory(migrated_engine),
            ctx,
            event_type="bad.test",
            target_entity_type="user",
            target_entity_id=user.id,
            payload_json={"patient_name": "NAO PERMITIDO"},
        )

    # ORM tamper blocked
    row = InstitutionalService.list_audit_events(db_session, ctx)[0]
    row.event_type = "orm.tamper"
    with pytest.raises(ValueError, match="append-only"):
        db_session.flush()
    db_session.rollback()

    row = InstitutionalService.list_audit_events(db_session, ctx)[0]
    db_session.delete(row)
    with pytest.raises(ValueError, match="append-only"):
        db_session.flush()
    db_session.rollback()

    # Raw SQL UPDATE and DELETE bypassing ORM must be rejected by DB triggers!
    with pytest.raises((IntegrityError, OperationalError, Exception)) as upd_exc:
        with migrated_engine.begin() as conn:
            conn.execute(
                text("UPDATE audit_events SET event_type = 'sql.tampered' WHERE id = :id"),
                {"id": row.id},
            )
    assert "append-only" in str(upd_exc.value).lower()

    with pytest.raises((IntegrityError, OperationalError, Exception)) as del_exc:
        with migrated_engine.begin() as conn:
            conn.execute(text("DELETE FROM audit_events WHERE id = :id"), {"id": row.id})
    assert "append-only" in str(del_exc.value).lower()

    # Cross-org actor rejected by FK fk_audit_events_org_actor even bypassing service
    bad_actor_event = AuditEvent(
        organization_id=org.id,
        schema_version=AUDIT_SCHEMA_VERSION,
        sequence_number=99,
        actor_user_id="00000000-0000-0000-0000-000000000000",
        event_type="bad.actor",
        target_entity_type="organization",
        target_entity_id=org.id,
        payload_json={"ok": True},
        prev_event_hash="0" * 64,
        event_hash="a" * 64,
    )
    db_session.add(bad_actor_event)
    with pytest.raises(IntegrityError):
        db_session.flush()
    db_session.rollback()

    assert InstitutionalService.verify_audit_chain(db_session, ctx) is True


def test_audit_concurrent_appends_single_and_multi_tenant_stay_linear(migrated_engine) -> None:
    session_factory = create_session_factory(migrated_engine)
    with session_factory() as setup_session:
        org_a = InstitutionalService.create_organization(
            setup_session, OrganizationCreateInput(slug="conc-org-a", name="Concurrent A")
        )
        org_b = InstitutionalService.create_organization(
            setup_session, OrganizationCreateInput(slug="conc-org-b", name="Concurrent B")
        )
        setup_session.commit()
        org_a_id, org_b_id = org_a.id, org_b.id

    def _worker(org_id: str, idx: int) -> None:
        InstitutionalService.append_audit_event_atomic(
            session_factory,
            TenantContext(organization_id=org_id),
            event_type="concurrent.probe",
            target_entity_type="organization",
            target_entity_id=org_id,
            payload_json={"worker_idx": idx},
        )

    tasks = [(org_a_id, i) for i in range(8)] + [(org_b_id, i) for i in range(6)]
    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_worker, oid, idx) for oid, idx in tasks]
        for fut in futures:
            fut.result()

    with session_factory() as verify_session:
        ctx_a = TenantContext(organization_id=org_a_id)
        ctx_b = TenantContext(organization_id=org_b_id)
        events_a = InstitutionalService.list_audit_events(verify_session, ctx_a)
        events_b = InstitutionalService.list_audit_events(verify_session, ctx_b)

        assert [e.sequence_number for e in events_a] == list(range(1, 9))
        assert [e.sequence_number for e in events_b] == list(range(1, 7))
        assert InstitutionalService.verify_audit_chain_detailed(verify_session, ctx_a).valid is True
        assert InstitutionalService.verify_audit_chain_detailed(verify_session, ctx_b).valid is True


def test_audit_verifier_detects_every_tampering_mode_on_detached_copies(
    db_session: Session,
) -> None:
    org = InstitutionalService.create_organization(
        db_session, OrganizationCreateInput(slug="verify-tamper", name="Verify Tamper")
    )
    user = InstitutionalService.create_user(
        db_session, UserCreateInput(email="verif@exemplo.invalid", display_name="Verificador")
    )
    ctx = TenantContext(organization_id=org.id)
    InstitutionalService.assign_membership(
        db_session, ctx, MembershipAssignInput(user_id=user.id, role=OrganizationRole.ORG_ADMIN)
    )
    act_ctx = TenantContext(organization_id=org.id, actor_user_id=user.id)
    for idx in range(3):
        InstitutionalService.create_case(
            db_session,
            act_ctx,
            type_case := __import__("app.schemas.tenant", fromlist=["DocumentCaseCreateInput"]).DocumentCaseCreateInput(
                case_code=f"SYN-AUD-{idx}"
            ),
        )
    del type_case
    db_session.commit()

    persisted = InstitutionalService.list_audit_events(db_session, ctx)
    assert len(persisted) == 4

    def _clone() -> list[_DetachedEvent]:
        return [
            _DetachedEvent(
                organization_id=e.organization_id,
                schema_version=e.schema_version,
                sequence_number=e.sequence_number,
                actor_user_id=e.actor_user_id,
                event_type=e.event_type,
                target_entity_type=e.target_entity_type,
                target_entity_id=e.target_entity_id,
                payload_json=dict(e.payload_json),
                prev_event_hash=e.prev_event_hash,
                event_hash=e.event_hash,
                created_at=e.created_at,
            )
            for e in persisted
        ]

    # Clean baseline
    assert verify_event_sequence(_clone(), organization_id=org.id).valid is True

    # 1. Middle event removed (gap)
    c = _clone()
    del c[1]
    res = verify_event_sequence(c, organization_id=org.id)
    assert not res.valid and res.failure_reason == "sequence_gap_or_reorder"

    # 2. First event removed
    c = _clone()
    del c[0]
    assert not verify_event_sequence(c, organization_id=org.id).valid

    # 3. Payload altered
    c = _clone()
    c[2].payload_json["tampered"] = True
    res = verify_event_sequence(c, organization_id=org.id)
    assert not res.valid and res.failure_reason == "event_hash_mismatch"

    # 4. Actor altered
    c = _clone()
    c[1].actor_user_id = "other-actor"
    assert not verify_event_sequence(c, organization_id=org.id).valid

    # 5. Reordered events
    c = _clone()
    c[1], c[2] = c[2], c[1]
    assert not verify_event_sequence(c, organization_id=org.id).valid

    # 6. Duplicate sequence number
    c = _clone()
    c[2].sequence_number = 2
    assert not verify_event_sequence(c, organization_id=org.id).valid

    # 7. Broken previous hash
    c = _clone()
    c[2].prev_event_hash = "f" * 64
    res = verify_event_sequence(c, organization_id=org.id)
    assert not res.valid and res.failure_reason == "prev_event_hash_mismatch"

    # 8. Cross-org event injection
    c = _clone()
    c[2].organization_id = "other-org"
    res = verify_event_sequence(c, organization_id=org.id)
    assert not res.valid and res.failure_reason == "cross_organization_event_detected"
