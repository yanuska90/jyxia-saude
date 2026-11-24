"""Comprehensive tests for Etapa 3.3.2 async durable processing queue, worker, leases, retries, and RBAC API."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
import random
import threading
import time
from typing import Any

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app import worker as worker_cli
from app.core.config import Settings
from app.core.constants import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CaseReadinessState,
    DocumentKind,
    IDEMPOTENCY_KEY_HEADER_NAME,
    OrganizationRole,
    ProcessingStatus,
    ProcessingStepType,
    SESSION_COOKIE_NAME,
)
from app.core.rbac import permissions_for_role
from app.core.session_crypto import hmac_token_digest
from app.db.base import new_uuid, utc_now
from app.db.session import apply_pg_rls_context, create_session_factory
from app.main import create_app
from app.models.entities import ProcessingRun
from app.repositories.identity import IdentityAndSessionRepository
from app.repositories.institutional import (
    AuditEventRepository,
    CaseAndDocumentRepository,
    LeaseOwnershipError,
    OrganizationRepository,
    ProcessingQueueRepository,
)
from app.schemas.tenant import TenantContext
from app.services.institutional_service import InstitutionalService
from app.services.processing_worker import ProcessingWorker, TransientProcessingError
from app.services.storage import LocalControlledSyntheticStorage

_VALID_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n"
    b"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n"
    b"xref\n0 4\n0000000000 65535 f \n"
    b"trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n140\n%%EOF\n"
)


def _make_minimal_png(width: int = 2, height: int = 2) -> bytes:
    import struct
    import zlib

    def _chunk(ctype: bytes, payload: bytes) -> bytes:
        crc = zlib.crc32(ctype + payload) & 0xFFFFFFFF
        return struct.pack(">I", len(payload)) + ctype + payload + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw_scanlines = b"".join(b"\x00" + (b"\x10\x20\x30" * width) for _ in range(height))
    idat = zlib.compress(raw_scanlines)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", ihdr)
        + _chunk(b"IDAT", idat)
        + _chunk(b"IEND", b"")
    )


_VALID_PNG = _make_minimal_png()


def _render_url(engine) -> str:
    return engine.url.render_as_string(hide_password=False)


def _create_app_settings(app_engine, tmp_path: Path) -> tuple[Settings, Path]:
    storage_root = tmp_path / "synthetic_storage"
    storage_root.mkdir(parents=True, exist_ok=True)
    settings = Settings(
        env="test",
        database_url=_render_url(app_engine),
        storage_root=storage_root.as_posix(),
        allow_local_synthetic_storage=True,
        max_document_bytes=20 * 1024 * 1024,
        app_base_url="http://127.0.0.1:8000",
        cors_allowed_origins=("http://127.0.0.1:8000",),
        session_cookie_secure=False,
        worker_retry_backoff_min_seconds=0.05,
        worker_retry_backoff_max_seconds=2.0,
        worker_retry_jitter_ratio=0.1,
    )
    return settings, storage_root


def _issue_session_cookies(
    owner_session,
    settings: Settings,
    *,
    user_id: str,
    external_identity_id: str,
    organization_id: str,
    tag: str,
) -> dict[str, Any]:
    raw_session = f"sess_{tag}_{new_uuid()}"
    raw_csrf = f"csrf_{tag}_{new_uuid()}"
    session_hash = hmac_token_digest(
        raw_session, secret=settings.session_secret, context="session_token"
    )
    csrf_hash = hmac_token_digest(
        raw_csrf, secret=settings.csrf_secret, context="csrf_token"
    )
    now = utc_now()
    IdentityAndSessionRepository.create_auth_session(
        owner_session,
        user_id=user_id,
        external_identity_id=external_identity_id,
        active_organization_id=organization_id,
        session_token_hash=session_hash,
        csrf_token_hash=csrf_hash,
        auth_method="oidc_pkce_mfa",
        acr="urn:jyxia:loa:mfa",
        amr_json=["pwd", "otp"],
        mfa_verified_at=now,
        oidc_auth_time=now,
        idle_expires_at=now + timedelta(minutes=30),
        absolute_expires_at=now + timedelta(hours=8),
        now=now,
    )
    return {
        "session_cookie": raw_session,
        "csrf_cookie": raw_csrf,
        "session_hash": session_hash,
    }


def _seed_workspace(migrated_engine, app_engine, tmp_path: Path) -> dict[str, Any]:
    settings, storage_root = _create_app_settings(app_engine, tmp_path)
    owner_factory = create_session_factory(migrated_engine)
    db = owner_factory()
    try:
        org_a = OrganizationRepository.create_organization(db, slug="proc-org-a", name="Proc Org A")
        org_b = OrganizationRepository.create_organization(db, slug="proc-org-b", name="Proc Org B")

        actors: dict[str, dict[str, Any]] = {}
        role_specs = (
            ("admin", OrganizationRole.ORG_ADMIN.value, org_a.id),
            ("operator", OrganizationRole.ADMIN_OPERATOR.value, org_a.id),
            ("reviewer", OrganizationRole.DOCUMENT_REVIEWER.value, org_a.id),
            ("auditor", OrganizationRole.AUDITOR_READONLY.value, org_a.id),
            ("readonly", OrganizationRole.READ_ONLY.value, org_a.id),
            ("org_b_admin", OrganizationRole.ORG_ADMIN.value, org_b.id),
        )
        for key, role_val, org_id in role_specs:
            user = OrganizationRepository.create_user(
                db,
                email=f"{key}.{new_uuid()[:6]}@jyxia.local",
                display_name=f"User {key}",
                mfa_enrolled=True,
            )
            OrganizationRepository.assign_membership(
                db,
                TenantContext(organization_id=org_id),
                user_id=user.id,
                role=role_val,
            )
            ext = IdentityAndSessionRepository.bind_external_identity(
                db,
                user_id=user.id,
                issuer="https://idp.jyxia.local/realms/proc",
                subject=f"sub-{key}-{new_uuid()[:8]}",
                email_at_binding=user.email,
            )
            creds = _issue_session_cookies(
                db,
                settings,
                user_id=user.id,
                external_identity_id=ext.id,
                organization_id=org_id,
                tag=key,
            )
            actors[key] = {
                "user_id": user.id,
                "organization_id": org_id,
                "role": role_val,
                **creds,
            }

        case_a = CaseAndDocumentRepository.create_case(
            db,
            TenantContext(organization_id=org_a.id, actor_user_id=actors["admin"]["user_id"]),
            case_code="PROC-CASE-A1",
            external_reference=None,
            procedure_reference="Conferencia processamento assincrono A",
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        case_b = CaseAndDocumentRepository.create_case(
            db,
            TenantContext(organization_id=org_b.id, actor_user_id=actors["org_b_admin"]["user_id"]),
            case_code="PROC-CASE-B1",
            external_reference=None,
            procedure_reference="Conferencia processamento assincrono B",
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        db.commit()
        return {
            "settings": settings,
            "storage_root": storage_root,
            "org_a_id": org_a.id,
            "org_b_id": org_b.id,
            "case_a_id": case_a.id,
            "case_b_id": case_b.id,
            "actors": actors,
        }
    finally:
        db.close()


def _auth_client(app, actor: dict[str, Any]) -> tuple[TestClient, dict[str, str]]:
    client = TestClient(app)
    client.cookies.set(SESSION_COOKIE_NAME, actor["session_cookie"])
    client.cookies.set(CSRF_COOKIE_NAME, actor["csrf_cookie"])
    headers = {
        CSRF_HEADER_NAME: actor["csrf_cookie"],
        "Origin": "http://127.0.0.1:8000",
    }
    return client, headers


def test_upload_atomically_creates_queued_run_and_compensates_on_audit_failure(
    migrated_engine, app_engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]

    with _auth_client(app, env["actors"]["admin"])[0] as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        headers = {
            CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
            "Origin": "http://127.0.0.1:8000",
        }
        resp = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "upload_queue_test"},
            files={"file": ("laudo-inicial.pdf", _VALID_PDF, "application/pdf")},
        )
        assert resp.status_code == 201, resp.text
        body = resp.json()
        run_summary = body["initial_processing_run"]
        assert run_summary is not None
        assert run_summary["status"] == ProcessingStatus.QUEUED.value
        assert run_summary["step_type"] == ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value
        assert run_summary["attempt_count"] == 0
        assert run_summary["max_attempts"] == 5
        assert run_summary["started_at"] is None
        assert run_summary["finished_at"] is None
        assert run_summary["readable"] is False
        assert run_summary["readiness_state"] is None
        assert run_summary["administrative_only"] is True
        assert run_summary["clinical_approval"] is False

    owner_session = create_session_factory(migrated_engine)()
    try:
        events = AuditEventRepository.list_events(
            owner_session, TenantContext(organization_id=org_a_id)
        )
        assert [e.event_type for e in events] == ["document.ingested", "processing_run.queued"]
        assert AuditEventRepository.verify_chain_detailed(
            owner_session, TenantContext(organization_id=org_a_id)
        ).valid
        files_before = list(env["storage_root"].rglob("*"))
    finally:
        owner_session.close()

    # Failure compensation: if AuditEventRepository.append_event fails during upload transaction,
    # neither orphan physical file nor orphan ProcessingRun/DocumentVersion may remain.
    def _boom_append(*_args, **_kwargs):
        raise RuntimeError("simulated_audit_write_failure")

    monkeypatch.setattr(AuditEventRepository, "append_event", staticmethod(_boom_append))
    with TestClient(app, raise_server_exceptions=False) as fail_client:
        fail_client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        fail_client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        fail_resp = fail_client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers={
                CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
                "Origin": "http://127.0.0.1:8000",
            },
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "compensation_test"},
            files={"file": ("orphan-check.pdf", _VALID_PDF, "application/pdf")},
        )
        assert fail_resp.status_code == 500

    monkeypatch.undo()
    files_after = list(env["storage_root"].rglob("*"))
    assert files_after == files_before

    verify_session = create_session_factory(migrated_engine)()
    try:
        apply_pg_rls_context(verify_session, organization_id=org_a_id)
        all_runs = list(
            verify_session.scalars(
                select(ProcessingRun).where(ProcessingRun.organization_id == org_a_id)
            )
        )
        assert len(all_runs) == 1
    finally:
        verify_session.close()


def test_worker_executes_verify_object_integrity_end_to_end_and_preserves_sanitized_contract(
    migrated_engine, app_engine, worker_engine, tmp_path: Path
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["operator"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["operator"]["csrf_cookie"])
        headers = {
            CSRF_HEADER_NAME: env["actors"]["operator"]["csrf_cookie"],
            "Origin": "http://127.0.0.1:8000",
        }
        up_pdf = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "pdf_verify"},
            files={"file": ("doc1.pdf", _VALID_PDF, "application/pdf")},
        )
        up_png = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.IMAGEM.value, "source_label": "png_verify"},
            files={"file": ("img1.png", _VALID_PNG, "image/png")},
        )
        assert up_pdf.status_code == 201 and up_png.status_code == 201
        run_pdf_id = up_pdf.json()["initial_processing_run"]["processing_run_id"]
        run_png_id = up_png.json()["initial_processing_run"]["processing_run_id"]

    storage = LocalControlledSyntheticStorage(
        env["storage_root"], enabled=True, max_bytes=20 * 1024 * 1024
    )
    worker = ProcessingWorker(
        create_session_factory(worker_engine),
        storage,
        env["settings"],
        worker_id="unit-integrity-worker",
    )
    stats = worker.process_one_cycle(max_jobs=10)
    assert stats.claimed == 5
    assert stats.succeeded == 5
    assert stats.failed == 0

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["reviewer"]["session_cookie"])
        list_resp = client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs"
        )
        assert list_resp.status_code == 200
        payload = list_resp.json()
        assert payload["total"] == 5
        assert {item["step_type"] for item in payload["processing_runs"]} == {
            ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
            ProcessingStepType.EXTRACT_PDF_TEXT.value,
            ProcessingStepType.COMPARE_CONSISTENCY.value,
        }

        for run_id in (run_pdf_id, run_png_id):
            detail_resp = client.get(
                f"/api/v1/organizations/{org_a_id}/processing-runs/{run_id}"
            )
            assert detail_resp.status_code == 200
            d = detail_resp.json()
            assert d["status"] == ProcessingStatus.SUCCEEDED.value
            assert d["attempt_count"] == 1
            assert d["started_at"] is not None and d["finished_at"] is not None
            assert d["readable"] is False
            assert d["readiness_state"] is None
            assert d["administrative_only"] is True
            assert d["clinical_approval"] is False
            assert d["result_json"]["sha256_verified"] is True
            assert d["result_json"]["byte_size_verified"] is True
            assert d["result_json"]["structural_validation_passed"] is True
            assert d["result_json"]["clinical_approval"] is False
            assert d["result_json"]["administrative_only"] is True

            raw_text = detail_resp.text
            assert "lease_token" not in raw_text
            assert "storage_key" not in raw_text
            assert env["storage_root"].as_posix() not in raw_text
            assert "synthetic_storage" not in raw_text

    owner_session = create_session_factory(migrated_engine)()
    try:
        events = AuditEventRepository.list_events(
            owner_session, TenantContext(organization_id=org_a_id)
        )
        event_types = [e.event_type for e in events]
        assert event_types.count("processing_run.queued") == 5
        assert event_types.count("processing_run.started") == 5
        assert event_types.count("processing_run.succeeded") == 3
        assert event_types.count("processing_run.abstained") == 2
        assert AuditEventRepository.verify_chain_detailed(
            owner_session, TenantContext(organization_id=org_a_id)
        ).valid
    finally:
        owner_session.close()


def test_transient_failure_backoff_retry_recovery_and_max_attempts_exhaustion(
    migrated_engine, app_engine, worker_engine, tmp_path: Path
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        headers = {
            CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
            "Origin": "http://127.0.0.1:8000",
        }
        up1 = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "transient_recover"},
            files={"file": ("recover.pdf", _VALID_PDF, "application/pdf")},
        )
        up2 = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "transient_exhaust"},
            files={"file": ("exhaust.pdf", _VALID_PDF, "application/pdf")},
        )
        assert up1.status_code == 201 and up2.status_code == 201
        run_recover_id = up1.json()["initial_processing_run"]["processing_run_id"]
        run_exhaust_id = up2.json()["initial_processing_run"]["processing_run_id"]

    # Bound max_attempts=2 on run_exhaust so transient exhaustion completes fast cleanly
    owner_db = create_session_factory(migrated_engine)()
    try:
        apply_pg_rls_context(owner_db, organization_id=org_a_id)
        owner_db.execute(
            text("UPDATE processing_runs SET max_attempts = 2 WHERE id = :rid"),
            {"rid": run_exhaust_id},
        )
        owner_db.commit()
    finally:
        owner_db.close()

    storage = LocalControlledSyntheticStorage(
        env["storage_root"], enabled=True, max_bytes=20 * 1024 * 1024
    )
    settings_retry = Settings(
        env="test",
        database_url=_render_url(app_engine),
        storage_root=env["storage_root"].as_posix(),
        worker_retry_backoff_min_seconds=0.8,
        worker_retry_backoff_max_seconds=2.0,
        worker_retry_jitter_ratio=0.05,
    )

    # Exponential backoff math check
    w_math = ProcessingWorker(
        create_session_factory(worker_engine),
        storage,
        Settings(
            env="test",
            worker_retry_backoff_min_seconds=2.0,
            worker_retry_backoff_max_seconds=10.0,
            worker_retry_jitter_ratio=0.0,
        ),
        rng=random.Random(42),
    )
    assert w_math.compute_retry_delay_seconds(attempt_count=1) == pytest.approx(2.0)
    assert w_math.compute_retry_delay_seconds(attempt_count=2) == pytest.approx(4.0)
    assert w_math.compute_retry_delay_seconds(attempt_count=3) == pytest.approx(8.0)
    assert w_math.compute_retry_delay_seconds(attempt_count=4) == pytest.approx(10.0)

    # Temporarily make storage unavailable -> attempt 1 sends both runs to retry_wait
    storage_down = LocalControlledSyntheticStorage(
        env["storage_root"], enabled=False, max_bytes=20 * 1024 * 1024
    )
    w_down = ProcessingWorker(
        create_session_factory(worker_engine),
        storage_down,
        settings_retry,
        worker_id="retry-worker-1",
    )
    stats1 = w_down.process_one_cycle(max_jobs=10)
    assert stats1.claimed == 2
    assert stats1.retried == 2
    assert stats1.succeeded == 0

    # Immediately polling before backoff elapses claims 0 jobs
    immediate = w_down.process_one_cycle(max_jobs=10)
    assert immediate.claimed == 0

    time.sleep(0.95)

    # Attempt 2: keep run_exhaust failing transiently so it hits max_attempts=2 -> FAILED,
    # while run_recover succeeds once storage is back.
    def _selective_step(claimed, st, cfg):
        if claimed.run_id == run_exhaust_id:
            raise TransientProcessingError("SIMULATED_IO_TIMEOUT", "Upstream read timed out.")
        from app.services.processing_worker import execute_verify_object_integrity_step

        return execute_verify_object_integrity_step(claimed, st, cfg)

    w_up = ProcessingWorker(
        create_session_factory(worker_engine),
        storage,
        settings_retry,
        worker_id="retry-worker-2",
        step_executor=_selective_step,
        step_types=ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
    )
    stats2 = w_up.process_one_cycle(max_jobs=10)
    assert stats2.claimed == 2
    assert stats2.succeeded == 1
    assert stats2.failed == 1

    # No third claim occurs because run_exhaust reached max_attempts=2 -> terminal failed
    assert w_up.process_one_cycle(max_jobs=10).claimed == 0

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["auditor"]["session_cookie"])
        rec = client.get(
            f"/api/v1/organizations/{org_a_id}/processing-runs/{run_recover_id}"
        ).json()
        exh = client.get(
            f"/api/v1/organizations/{org_a_id}/processing-runs/{run_exhaust_id}"
        ).json()
        assert rec["status"] == ProcessingStatus.SUCCEEDED.value
        assert rec["attempt_count"] == 2
        assert rec["last_error_code"] is None
        assert exh["status"] == ProcessingStatus.FAILED.value
        assert exh["attempt_count"] == 2
        assert exh["last_error_code"] == "SIMULATED_IO_TIMEOUT"
        assert exh["finished_at"] is not None

    verify_db = create_session_factory(migrated_engine)()
    try:
        assert AuditEventRepository.verify_chain_detailed(
            verify_db, TenantContext(organization_id=org_a_id)
        ).valid
    finally:
        verify_db.close()


def test_permanent_failures_do_not_retry_and_sanitize_error_details(
    migrated_engine, app_engine, worker_engine, tmp_path: Path
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        headers = {
            CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
            "Origin": "http://127.0.0.1:8000",
        }
        up_missing = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "missing_blob"},
            files={"file": ("missing.pdf", _VALID_PDF, "application/pdf")},
        ).json()
        up_tampered = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "tampered_blob"},
            files={"file": ("tampered.pdf", _VALID_PDF, "application/pdf")},
        ).json()
        up_corrupt = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "corrupt_blob"},
            files={"file": ("corrupt.pdf", _VALID_PDF, "application/pdf")},
        ).json()

    run_missing_id = up_missing["initial_processing_run"]["processing_run_id"]
    run_tampered_id = up_tampered["initial_processing_run"]["processing_run_id"]
    run_corrupt_id = up_corrupt["initial_processing_run"]["processing_run_id"]

    # Mutate stored files on disk via storage_key resolved from owner DB
    owner_db = create_session_factory(migrated_engine)()
    try:
        ctx_a = TenantContext(organization_id=org_a_id)
        v_missing = CaseAndDocumentRepository.get_document_version(
            owner_db, ctx_a, up_missing["current_version"]["version_id"]
        )
        v_tampered = CaseAndDocumentRepository.get_document_version(
            owner_db, ctx_a, up_tampered["current_version"]["version_id"]
        )
        v_corrupt = CaseAndDocumentRepository.get_document_version(
            owner_db, ctx_a, up_corrupt["current_version"]["version_id"]
        )
        assert v_missing and v_tampered and v_corrupt
        (env["storage_root"] / v_missing.storage_key).unlink()
        # Same size change / checksum tamper
        tampered_bytes = b"%PDF-1.4\n" + b"X" * (len(_VALID_PDF) - 15) + b"\n%%EOF"
        (env["storage_root"] / v_tampered.storage_key).write_bytes(tampered_bytes)
        (env["storage_root"] / v_corrupt.storage_key).write_bytes(b"NOT_A_PDF_AT_ALL_1234567890")
    finally:
        owner_db.close()

    storage = LocalControlledSyntheticStorage(
        env["storage_root"], enabled=True, max_bytes=20 * 1024 * 1024
    )
    worker = ProcessingWorker(
        create_session_factory(worker_engine),
        storage,
        env["settings"],
        worker_id="perm-fail-worker",
    )
    stats = worker.process_one_cycle(max_jobs=10)
    assert stats.claimed == 3
    assert stats.failed == 3
    assert stats.retried == 0
    # Zero retries scheduled
    assert worker.process_one_cycle(max_jobs=10).claimed == 0

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["readonly"]["session_cookie"])
        d_miss = client.get(
            f"/api/v1/organizations/{org_a_id}/processing-runs/{run_missing_id}"
        ).json()
        d_tamp = client.get(
            f"/api/v1/organizations/{org_a_id}/processing-runs/{run_tampered_id}"
        ).json()
        d_corr = client.get(
            f"/api/v1/organizations/{org_a_id}/processing-runs/{run_corrupt_id}"
        ).json()
        assert d_miss["status"] == ProcessingStatus.FAILED.value and d_miss["attempt_count"] == 1
        assert d_miss["last_error_code"] == "OBJECT_NOT_FOUND"
        assert d_tamp["status"] == ProcessingStatus.FAILED.value and d_tamp["attempt_count"] == 1
        assert d_tamp["last_error_code"] == "INTEGRITY_MISMATCH"
        assert d_corr["status"] == ProcessingStatus.FAILED.value and d_corr["attempt_count"] == 1
        assert d_corr["last_error_code"] == "STRUCTURAL_VALIDATION_FAILED"
        for payload_txt in (str(d_miss), str(d_tamp), str(d_corr)):
            assert env["storage_root"].as_posix() not in payload_txt

    # Explicit diagnostic sanitization check when an exception message includes path/secret patterns
    from app.repositories.institutional import sanitize_technical_error_detail

    scrubbed = sanitize_technical_error_detail(
        r"Read failure on C:\Users\internal\synthetic_storage\secret.pdf with Bearer tok_99911"
    )
    assert "[PATH_REDACTED]" in scrubbed
    assert "tok_99911" not in scrubbed
    assert "synthetic_storage" not in scrubbed


def test_idempotency_active_uniqueness_new_version_and_manual_reprocessing(
    migrated_engine, app_engine, worker_engine, tmp_path: Path
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        headers = {
            CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
            "Origin": "http://127.0.0.1:8000",
            IDEMPOTENCY_KEY_HEADER_NAME: "idem-upload-queue-01",
        }
        up1 = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "idem_test"},
            files={"file": ("idem.pdf", _VALID_PDF, "application/pdf")},
        )
        up2 = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=headers,
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "idem_test"},
            files={"file": ("idem.pdf", _VALID_PDF, "application/pdf")},
        )
        assert up1.status_code == 201 and up2.status_code == 200
        assert up2.json()["idempotent_replay"] is True
        doc_id = up1.json()["document_id"]
        ver_id = up1.json()["current_version"]["version_id"]
        run_1_id = up1.json()["initial_processing_run"]["processing_run_id"]
        assert up2.json()["initial_processing_run"]["processing_run_id"] == run_1_id

        # Active queued run blocks concurrent reprocess with 409
        csrf_headers = {
            CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
            "Origin": "http://127.0.0.1:8000",
        }
        conflict = client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/reprocess",
            headers=csrf_headers,
        )
        assert conflict.status_code == 409

    # DB partial unique index also rejects concurrent active queued run
    owner_db = create_session_factory(migrated_engine)()
    try:
        with pytest.raises(IntegrityError):
            ProcessingQueueRepository.enqueue_run(
                owner_db,
                TenantContext(
                    organization_id=org_a_id, actor_user_id=env["actors"]["admin"]["user_id"]
                ),
                document_version_id=ver_id,
                idempotency_key="direct-duplicate-active-run",
            )
        owner_db.rollback()
    finally:
        owner_db.close()

    storage = LocalControlledSyntheticStorage(
        env["storage_root"], enabled=True, max_bytes=20 * 1024 * 1024
    )
    worker = ProcessingWorker(
        create_session_factory(worker_engine),
        storage,
        env["settings"],
        worker_id="reprocess-worker",
    )
    assert worker.process_one_cycle(max_jobs=5).succeeded == 2

    # Reprocess after terminal SUCCEEDED creates a NEW ProcessingRun while preserving history
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        re_headers = {
            CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
            "Origin": "http://127.0.0.1:8000",
            IDEMPOTENCY_KEY_HEADER_NAME: "reprocess-idem-001",
        }
        r_new = client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/reprocess",
            headers=re_headers,
        )
        r_replay = client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/reprocess",
            headers=re_headers,
        )
        assert r_new.status_code == 201 and r_replay.status_code == 200
        run_2_id = r_new.json()["processing_run_id"]
        assert run_2_id != run_1_id
        assert r_replay.json()["processing_run_id"] == run_2_id

        # Registering a new document version (v2) enqueues its own queued run
        owner_db = create_session_factory(migrated_engine)()
        try:
            ver_2 = InstitutionalService.store_and_register_document_version(
                owner_db,
                TenantContext(
                    organization_id=org_a_id,
                    actor_user_id=env["actors"]["admin"]["user_id"],
                    session_token_hash=env["actors"]["admin"]["session_hash"],
                ),
                storage=storage,
                document_id=doc_id,
                version_number=2,
                mime_type="application/pdf",
                content=_VALID_PDF + b"\n",
                original_filename="idem-v2.pdf",
                enqueue_processing=True,
            )
            owner_db.commit()
            ver_2_id = ver_2.id
        finally:
            owner_db.close()

        assert worker.process_one_cycle(max_jobs=10).succeeded == 4
        runs_list = client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs"
        ).json()
        assert runs_list["total"] == 6
        ver_1_runs = client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs",
            params={"document_version_id": ver_id},
        ).json()
        assert ver_1_runs["total"] == 4
        ver_2_runs = client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs",
            params={"document_version_id": ver_2_id},
        ).json()
        assert ver_2_runs["total"] == 2


def test_lease_expiry_reclaim_stolen_lease_fencing_and_max_attempts_on_expired_lease(
    migrated_engine, app_engine, worker_engine, tmp_path: Path
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        up = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers={
                CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
                "Origin": "http://127.0.0.1:8000",
            },
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "lease_fencing"},
            files={"file": ("lease.pdf", _VALID_PDF, "application/pdf")},
        ).json()
    run_id = up["initial_processing_run"]["processing_run_id"]

    # Set max_attempts=2 so we test BOTH 1st reclaim (queued) and 2nd reclaim (failed)
    owner_db = create_session_factory(migrated_engine)()
    try:
        apply_pg_rls_context(owner_db, organization_id=org_a_id)
        owner_db.execute(
            text("UPDATE processing_runs SET max_attempts = 2 WHERE id = :rid"),
            {"rid": run_id},
        )
        owner_db.commit()
    finally:
        owner_db.close()

    worker_factory = create_session_factory(worker_engine)
    _tok1, tok1_hash = ProcessingQueueRepository.generate_lease_proof()
    claim_db = worker_factory()
    try:
        claimed_1 = ProcessingQueueRepository.claim_next_run(
            claim_db, worker_id="crashed-worker-1", lease_token_hash=tok1_hash, lease_seconds=30
        )
        assert claimed_1 is not None and claimed_1.attempt_count == 1
    finally:
        claim_db.close()

    # Wrong lease token fails immediately even before expiration
    bad_db = worker_factory()
    try:
        with pytest.raises(LeaseOwnershipError):
            ProcessingQueueRepository.complete_run(
                bad_db,
                run_id=run_id,
                worker_id="crashed-worker-1",
                lease_token_hash="f" * 64,
                result_json={"sha256_verified": True},
            )
    finally:
        bad_db.close()

    # Force lease expiry
    exp_db = create_session_factory(migrated_engine)()
    try:
        apply_pg_rls_context(exp_db, organization_id=org_a_id)
        exp_db.execute(
            text("UPDATE processing_runs SET lease_expires_at = :exp WHERE id = :rid"),
            {"exp": utc_now() - timedelta(seconds=30), "rid": run_id},
        )
        exp_db.commit()
    finally:
        exp_db.close()

    # Late worker trying to complete with expired lease is rejected
    late_db = worker_factory()
    try:
        with pytest.raises(LeaseOwnershipError):
            ProcessingQueueRepository.complete_run(
                late_db,
                run_id=run_id,
                worker_id="crashed-worker-1",
                lease_token_hash=tok1_hash,
                result_json={"sha256_verified": True},
            )
    finally:
        late_db.close()

    # Reclaim puts job back to QUEUED (attempt_count stays 1 < max_attempts=2)
    reclaimed = ProcessingQueueRepository.reclaim_expired_leases(
        worker_factory, reclaimer_worker_id="reclaimer-worker", limit=5
    )
    assert reclaimed == 1

    # 2nd worker claims (attempt_count=2) and also crashes with expired lease
    _tok2, tok2_hash = ProcessingQueueRepository.generate_lease_proof()
    claim2_db = worker_factory()
    try:
        claimed_2 = ProcessingQueueRepository.claim_next_run(
            claim2_db, worker_id="crashed-worker-2", lease_token_hash=tok2_hash, lease_seconds=30
        )
        assert claimed_2 is not None and claimed_2.attempt_count == 2
    finally:
        claim2_db.close()

    exp2_db = create_session_factory(migrated_engine)()
    try:
        apply_pg_rls_context(exp2_db, organization_id=org_a_id)
        exp2_db.execute(
            text("UPDATE processing_runs SET lease_expires_at = :exp WHERE id = :rid"),
            {"exp": utc_now() - timedelta(seconds=30), "rid": run_id},
        )
        exp2_db.commit()
    finally:
        exp2_db.close()

    # Reclaiming when attempt_count == max_attempts transitions directly to FAILED
    assert (
        ProcessingQueueRepository.reclaim_expired_leases(
            worker_factory, reclaimer_worker_id="reclaimer-worker", limit=5
        )
        == 1
    )

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        d = client.get(f"/api/v1/organizations/{org_a_id}/processing-runs/{run_id}").json()
        assert d["status"] == ProcessingStatus.FAILED.value
        assert d["last_error_code"] == "LEASE_EXPIRED_MAX_ATTEMPTS"
        assert d["attempt_count"] == 2
        assert d["finished_at"] is not None

    audit_db = create_session_factory(migrated_engine)()
    try:
        assert AuditEventRepository.verify_chain_detailed(
            audit_db, TenantContext(organization_id=org_a_id)
        ).valid
    finally:
        audit_db.close()


def test_http_rbac_csrf_and_multitenant_isolation_on_processing_endpoints(
    migrated_engine, app_engine, worker_engine, tmp_path: Path
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    org_b_id = env["org_b_id"]
    case_a_id = env["case_a_id"]

    with TestClient(app) as anon_client:
        assert (
            anon_client.get(
                f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs"
            ).status_code
            == 401
        )

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        up = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers={
                CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
                "Origin": "http://127.0.0.1:8000",
            },
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "rbac_scope"},
            files={"file": ("rbac.pdf", _VALID_PDF, "application/pdf")},
        ).json()
    doc_id = up["document_id"]
    ver_id = up["current_version"]["version_id"]
    run_id = up["initial_processing_run"]["processing_run_id"]

    storage = LocalControlledSyntheticStorage(
        env["storage_root"], enabled=True, max_bytes=20 * 1024 * 1024
    )
    ProcessingWorker(create_session_factory(worker_engine), storage, env["settings"]).process_one_cycle()

    # All 5 roles can READ processing runs; only org_admin and admin_operator can trigger reprocess
    for key in ("admin", "operator", "reviewer", "auditor", "readonly"):
        actor = env["actors"][key]
        with TestClient(app) as client:
            client.cookies.set(SESSION_COOKIE_NAME, actor["session_cookie"])
            client.cookies.set(CSRF_COOKIE_NAME, actor["csrf_cookie"])
            r_list = client.get(
                f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs"
            )
            r_det = client.get(f"/api/v1/organizations/{org_a_id}/processing-runs/{run_id}")
            assert r_list.status_code == 200
            assert r_det.status_code == 200

            # Missing CSRF fails with 403
            r_no_csrf = client.post(
                f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/reprocess"
            )
            assert r_no_csrf.status_code == 403

            role = OrganizationRole(actor["role"])
            r_re = client.post(
                f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/reprocess",
                headers={
                    CSRF_HEADER_NAME: actor["csrf_cookie"],
                    "Origin": "http://127.0.0.1:8000",
                },
            )
            from app.core.rbac import RbacPermission

            if RbacPermission.DOCUMENT_UPLOAD in permissions_for_role(role):
                assert r_re.status_code == 201
                ProcessingWorker(
                    create_session_factory(worker_engine), storage, env["settings"]
                ).process_one_cycle()
            else:
                assert r_re.status_code == 403

    # Cross-tenant isolation: Org B user cannot query Org A path or Org A run via Org B route
    org_b_actor = env["actors"]["org_b_admin"]
    with TestClient(app) as b_client:
        b_client.cookies.set(SESSION_COOKIE_NAME, org_b_actor["session_cookie"])
        b_client.cookies.set(CSRF_COOKIE_NAME, org_b_actor["csrf_cookie"])
        assert (
            b_client.get(
                f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs"
            ).status_code
            == 403
        )
        assert (
            b_client.get(
                f"/api/v1/organizations/{org_b_id}/processing-runs/{run_id}"
            ).status_code
            == 404
        )
        assert (
            b_client.get(
                f"/api/v1/organizations/{org_b_id}/cases/{case_a_id}/processing-runs"
            ).status_code
            == 404
        )
        assert (
            b_client.post(
                f"/api/v1/organizations/{org_b_id}/documents/{doc_id}/versions/{ver_id}/reprocess",
                headers={
                    CSRF_HEADER_NAME: org_b_actor["csrf_cookie"],
                    "Origin": "http://127.0.0.1:8000",
                },
            ).status_code
            == 404
        )


def test_worker_cli_once_graceful_shutdown_and_concurrent_workers(
    migrated_engine, app_engine, worker_engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        headers = {
            CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
            "Origin": "http://127.0.0.1:8000",
        }
        for idx in range(5):
            resp = client.post(
                f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
                headers=headers,
                data={"document_kind": DocumentKind.LAUDO.value, "source_label": f"conc_{idx}"},
                files={"file": (f"conc-{idx}.pdf", _VALID_PDF, "application/pdf")},
            )
            assert resp.status_code == 201

    storage = LocalControlledSyntheticStorage(
        env["storage_root"], enabled=True, max_bytes=20 * 1024 * 1024
    )
    w_factory = create_session_factory(worker_engine)
    w1 = ProcessingWorker(w_factory, storage, env["settings"], worker_id="conc-worker-a")
    w2 = ProcessingWorker(w_factory, storage, env["settings"], worker_id="conc-worker-b")
    with ThreadPoolExecutor(max_workers=2) as pool:
        f1 = pool.submit(w1.process_one_cycle, max_jobs=10)
        f2 = pool.submit(w2.process_one_cycle, max_jobs=10)
        s1, s2 = f1.result(), f2.result()
    assert s1.claimed + s2.claimed == 11
    assert s1.succeeded + s2.succeeded == 11

    # Standalone worker CLI (--once) execution
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        up_cli = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers={
                CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
                "Origin": "http://127.0.0.1:8000",
            },
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "cli_once"},
            files={"file": ("cli-once.pdf", _VALID_PDF, "application/pdf")},
        )
        assert up_cli.status_code == 201
        cli_run_id = up_cli.json()["initial_processing_run"]["processing_run_id"]

    cli_settings = Settings(
        env="test",
        database_url=_render_url(app_engine),
        worker_database_url=_render_url(worker_engine),
        storage_root=env["storage_root"].as_posix(),
        allow_local_synthetic_storage=True,
        worker_id="cli-once-worker",
        worker_poll_interval_seconds=0.05,
    )
    monkeypatch.setattr(worker_cli, "load_settings", lambda strict_database=False: cli_settings)
    assert worker_cli.main(["--once"]) == 0

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        cli_detail = client.get(
            f"/api/v1/organizations/{org_a_id}/processing-runs/{cli_run_id}"
        ).json()
        assert cli_detail["status"] == ProcessingStatus.SUCCEEDED.value

    # Graceful shutdown test on run_loop
    loop_worker = ProcessingWorker(w_factory, storage, cli_settings, worker_id="shutdown-worker")
    timer = threading.Timer(0.1, loop_worker.request_stop)
    timer.start()
    try:
        loop_summary = loop_worker.run_loop(handle_signals=False)
        assert loop_worker.stop_requested is True
        assert isinstance(loop_summary.succeeded, int)
    finally:
        timer.cancel()
