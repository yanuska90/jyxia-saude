"""Comprehensive tests for Etapa 3.3.1: authenticated document ingestion, file validation,
controlled synthetic storage, RBAC matrix, multi-tenant isolation, idempotency, and audit trail.
"""

from __future__ import annotations

from datetime import timedelta
import hashlib
import json
from pathlib import Path
import struct
from urllib.parse import parse_qs, urlparse
import zlib

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.core.constants import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    IDEMPOTENCY_KEY_HEADER_NAME,
    SESSION_COOKIE_NAME,
    CaseReadinessState,
    MembershipStatus,
    OrganizationRole,
)
from app.core.oidc import StandardOidcProviderAdapter
from app.core.rbac import AuthorizationDeniedError
from app.db.base import utc_now
from app.db.session import create_session_factory
from app.main import create_app
from app.models.entities import AuditEvent, AuthSession, Document, DocumentVersion, User
from app.repositories.identity import IdentityAndSessionRepository, SecurityAuditRepository
from app.repositories.institutional import (
    AuditEventRepository,
    CaseAndDocumentRepository,
    OrganizationRepository,
)
from app.schemas.tenant import TenantContext
from app.services.institutional_service import InstitutionalService
from app.services.storage import LocalControlledSyntheticStorage
from tests.backend.oidc_test_support import (
    MockOidcProviderState,
    _base_claims,
    _oidc_settings,
    _sign_id_token,
)

VALID_SYNTHETIC_PDF = (
    b"%PDF-1.4\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    b"trailer\n<< /Root 1 0 R >>\n"
    b"%%EOF\n"
)
VALID_SYNTHETIC_PDF_ALT = (
    b"%PDF-1.7\n"
    b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
    b"%%EOF\n"
)


def _build_valid_synthetic_png(width: int = 2, height: int = 2) -> bytes:
    def _chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack("!I4s", len(data), ctype) + data + struct.pack("!I", crc)

    ihdr = struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0)
    raw_scanlines = b"".join(b"\x00" + (b"\x10\x20\x30" * width) for _ in range(height))
    idat = zlib.compress(raw_scanlines)
    return b"\x89PNG\r\n\x1a\n" + _chunk(b"IHDR", ihdr) + _chunk(b"IDAT", idat) + _chunk(b"IEND", b"")


VALID_SYNTHETIC_PNG = _build_valid_synthetic_png()


def _login_bff(
    client: TestClient,
    idp: MockOidcProviderState,
    *,
    sub: str,
    email: str,
    code: str,
) -> tuple[str, str]:
    login_resp = client.get("/api/v1/auth/login?next=/cases", follow_redirects=False)
    assert login_resp.status_code == 302
    params = parse_qs(urlparse(login_resp.headers["location"]).query)
    state = params["state"][0]
    nonce = params["nonce"][0]
    challenge = params["code_challenge"][0]

    claims = _base_claims(issuer=idp.issuer, sub=sub, nonce=nonce)
    claims["email"] = email
    idp.issued_codes[code] = {
        "code_challenge": challenge,
        "id_token": _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=claims),
    }
    cb = client.get(f"/api/v1/auth/callback?code={code}&state={state}", follow_redirects=False)
    assert cb.status_code == 302
    sess_cookie = cb.cookies.get(SESSION_COOKIE_NAME)
    csrf_cookie = cb.cookies.get(CSRF_COOKIE_NAME)
    assert sess_cookie and csrf_cookie
    return sess_cookie, csrf_cookie


def _seed_two_tenants_and_roles(
    factory: sessionmaker[Session], issuer: str
) -> dict[str, str]:
    db = factory()
    try:
        org_a = OrganizationRepository.create_organization(db, slug="ingest-org-a", name="Ingest Org A")
        org_b = OrganizationRepository.create_organization(db, slug="ingest-org-b", name="Ingest Org B")
        case_a = CaseAndDocumentRepository.create_case(
            db,
            TenantContext(organization_id=org_a.id),
            case_code="ING-CASE-A1",
            external_reference="EXT-ING-A1",
            procedure_reference="PROC-SYN-A",
            declared_laterality="direita",
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        case_a2 = CaseAndDocumentRepository.create_case(
            db,
            TenantContext(organization_id=org_a.id),
            case_code="ING-CASE-A2",
            external_reference="EXT-ING-A2",
            procedure_reference="PROC-SYN-A2",
            declared_laterality="esquerda",
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        case_b = CaseAndDocumentRepository.create_case(
            db,
            TenantContext(organization_id=org_b.id),
            case_code="ING-CASE-B1",
            external_reference="EXT-ING-B1",
            procedure_reference="PROC-SYN-B",
            declared_laterality="bilateral",
            readiness_state=CaseReadinessState.PENDENTE.value,
        )

        ids: dict[str, str] = {
            "org_a_id": org_a.id,
            "org_b_id": org_b.id,
            "case_a_id": case_a.id,
            "case_a2_id": case_a2.id,
            "case_b_id": case_b.id,
        }
        for role in OrganizationRole:
            u = OrganizationRepository.create_user(
                db,
                email=f"ing.{role.value}@jyxia.local",
                display_name=f"Ingest {role.value}",
                mfa_enrolled=True,
            )
            m = OrganizationRepository.assign_membership(
                db,
                TenantContext(organization_id=org_a.id),
                user_id=u.id,
                role=role.value,
            )
            IdentityAndSessionRepository.bind_external_identity(
                db,
                user_id=u.id,
                issuer=issuer,
                subject=f"sub-ing-{role.value}",
            )
            ids[f"user_{role.value}_id"] = u.id
            ids[f"mem_{role.value}_id"] = m.id

        u_b = OrganizationRepository.create_user(
            db,
            email="ing.orgb.admin@jyxia.local",
            display_name="Ingest Org B Admin",
            mfa_enrolled=True,
        )
        OrganizationRepository.assign_membership(
            db,
            TenantContext(organization_id=org_b.id),
            user_id=u_b.id,
            role=OrganizationRole.ORG_ADMIN.value,
        )
        IdentityAndSessionRepository.bind_external_identity(
            db,
            user_id=u_b.id,
            issuer=issuer,
            subject="sub-ing-orgb-admin",
        )
        ids["user_b_id"] = u_b.id
        db.commit()
        return ids
    finally:
        db.close()


def test_document_upload_authentication_csrf_and_session_states(
    migrated_engine, tmp_path: Path
) -> None:
    """13.1: Verify BFF session, MFA, expiry, revocation, CSRF, user suspension, and membership checks."""
    idp = MockOidcProviderState()
    storage_dir = tmp_path / "JYXIA_LOCAL_WORK" / "synthetic_storage"
    settings = _oidc_settings(storage_root=str(storage_dir))
    storage = LocalControlledSyntheticStorage(storage_dir, enabled=True, max_bytes=1024 * 1024)
    factory = create_session_factory(migrated_engine)
    ids = _seed_two_tenants_and_roles(factory, idp.issuer)

    app = create_app(
        settings,
        engine=migrated_engine,
        oidc_adapter=StandardOidcProviderAdapter(settings, transport=idp.transport()),
        storage=storage,
    )
    upload_url = f"/api/v1/organizations/{ids['org_a_id']}/cases/{ids['case_a_id']}/documents"

    # 1. Anonymous upload MUST fail with 401
    with TestClient(app, base_url="http://127.0.0.1:8000") as anon_client:
        res_anon = anon_client.post(
            upload_url,
            files={"file": ("laudo.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
        )
        assert res_anon.status_code == 401

        # Direct Bearer token MUST be rejected with 401
        res_bearer = anon_client.post(
            upload_url,
            headers={"Authorization": "Bearer fake-jwt-token"},
            files={"file": ("laudo.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
        )
        assert res_bearer.status_code == 401

    # 2. Valid authenticated session: test CSRF defense then valid upload
    with TestClient(
        app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False
    ) as client:
        _, csrf_tok = _login_bff(
            client,
            idp,
            sub="sub-ing-org_admin",
            email="ing.org_admin@jyxia.local",
            code="c-auth-1",
        )

        # Missing CSRF header or untrusted Origin MUST fail 403
        assert (
            client.post(
                upload_url,
                headers={"Origin": "http://127.0.0.1:8000"},
                files={"file": ("laudo.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            ).status_code
            == 403
        )
        assert (
            client.post(
                upload_url,
                headers={"Origin": "https://evil.invalid", CSRF_HEADER_NAME: csrf_tok},
                files={"file": ("laudo.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            ).status_code
            == 403
        )

        # Valid session + valid CSRF + valid PDF -> 201 Created
        ok_res = client.post(
            upload_url,
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_tok},
            files={"file": ("laudo-sintetico.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            data={
                "document_kind": "laudo",
                "document_subfamily": "oftalmologia_sintetica",
                "source_label": "upload_autenticado_teste",
                "external_reference": "DOC-EXT-01",
                "description": "Documento sintetico de teste institucional",
            },
        )
        assert ok_res.status_code == 201
        body = ok_res.json()
        assert body["organization_id"] == ids["org_a_id"]
        assert body["case_id"] == ids["case_a_id"]
        assert body["document_kind"] == "laudo"
        assert body["created_by_user_id"] == ids["user_org_admin_id"]
        assert body["current_version"]["version_number"] == 1
        assert body["current_version"]["sha256_hex"] == hashlib.sha256(VALID_SYNTHETIC_PDF).hexdigest()
        assert body["current_version"]["byte_size"] == len(VALID_SYNTHETIC_PDF)
        assert body["current_version"]["mime_type"] == "application/pdf"
        assert body["current_version"]["original_filename"] == "laudo-sintetico.pdf"
        assert "storage_key" not in json.dumps(body)
        assert str(storage_dir) not in json.dumps(body)

        sess_id = client.get("/api/v1/auth/session").json()["session_id"]

        # 3. Expired session MUST fail 401
        db = factory()
        try:
            s_row = db.get(AuthSession, sess_id)
            assert s_row is not None
            past_created = utc_now() - timedelta(minutes=45)
            s_row.created_at = past_created
            s_row.mfa_verified_at = past_created
            s_row.oidc_auth_time = past_created
            s_row.last_seen_at = past_created
            s_row.idle_expires_at = utc_now() - timedelta(minutes=5)
            db.commit()
        finally:
            db.close()

        assert (
            client.post(
                upload_url,
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_tok},
                files={"file": ("laudo2.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            ).status_code
            == 401
        )

    # 4. Revoked session MUST fail 401
    with TestClient(app, base_url="http://127.0.0.1:8000") as rev_client:
        _, csrf_rev = _login_bff(
            rev_client,
            idp,
            sub="sub-ing-org_admin",
            email="ing.org_admin@jyxia.local",
            code="c-auth-rev",
        )
        rev_sess_id = rev_client.get("/api/v1/auth/session").json()["session_id"]
        db = factory()
        try:
            s_row = db.get(AuthSession, rev_sess_id)
            assert s_row is not None
            s_row.revoked_at = utc_now()
            s_row.revocation_reason = "test_manual_revoke"
            db.commit()
        finally:
            db.close()

        assert (
            rev_client.post(
                upload_url,
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_rev},
                files={"file": ("laudo3.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            ).status_code
            == 401
        )

    # 5. Suspended user & suspended membership MUST be rejected
    with TestClient(app, base_url="http://127.0.0.1:8000") as op_client:
        _, csrf_op = _login_bff(
            op_client,
            idp,
            sub="sub-ing-admin_operator",
            email="ing.admin_operator@jyxia.local",
            code="c-auth-op",
        )
        # Suspend membership -> 403
        db = factory()
        try:
            from app.models.entities import OrganizationMembership

            m_row = db.get(OrganizationMembership, ids["mem_admin_operator_id"])
            assert m_row is not None
            m_row.status = MembershipStatus.SUSPENDED.value
            db.commit()
        finally:
            db.close()

        assert (
            op_client.post(
                upload_url,
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_op},
                files={"file": ("laudo4.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            ).status_code
            == 403
        )

        # Suspend user -> 401
        db = factory()
        try:
            u_row = db.get(User, ids["user_admin_operator_id"])
            assert u_row is not None
            u_row.is_active = False
            db.commit()
        finally:
            db.close()

        assert (
            op_client.post(
                upload_url,
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_op},
                files={"file": ("laudo5.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            ).status_code
            == 401
        )


def test_document_upload_and_retrieval_five_role_rbac_matrix(
    migrated_engine, tmp_path: Path
) -> None:
    """13.2: Verify exact RBAC permissions for all 5 roles at both route and service layers."""
    idp = MockOidcProviderState()
    storage_dir = tmp_path / "JYXIA_LOCAL_WORK" / "rbac_storage"
    settings = _oidc_settings(storage_root=str(storage_dir))
    storage = LocalControlledSyntheticStorage(storage_dir, enabled=True, max_bytes=1024 * 1024)
    factory = create_session_factory(migrated_engine)
    ids = _seed_two_tenants_and_roles(factory, idp.issuer)

    app = create_app(
        settings,
        engine=migrated_engine,
        oidc_adapter=StandardOidcProviderAdapter(settings, transport=idp.transport()),
        storage=storage,
    )
    upload_url = f"/api/v1/organizations/{ids['org_a_id']}/cases/{ids['case_a_id']}/documents"

    # Expected upload status codes per role:
    # Only org_admin and admin_operator hold 'document:upload';
    # document_reviewer, auditor_readonly, and read_only MUST receive 403 Forbidden on upload!
    expected_upload_status: dict[OrganizationRole, int] = {
        OrganizationRole.ORG_ADMIN: 201,
        OrganizationRole.ADMIN_OPERATOR: 201,
        OrganizationRole.DOCUMENT_REVIEWER: 403,
        OrganizationRole.AUDITOR_READONLY: 403,
        OrganizationRole.READ_ONLY: 403,
    }

    uploaded_doc_id: str | None = None
    uploaded_ver_id: str | None = None

    for idx, role in enumerate(OrganizationRole):
        with TestClient(
        app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False
    ) as client:
            _, csrf_tok = _login_bff(
                client,
                idp,
                sub=f"sub-ing-{role.value}",
                email=f"ing.{role.value}@jyxia.local",
                code=f"c-rbac-{idx}",
            )
            payload = VALID_SYNTHETIC_PDF if idx % 2 == 0 else VALID_SYNTHETIC_PNG
            mime = "application/pdf" if idx % 2 == 0 else "image/png"
            ext = "pdf" if idx % 2 == 0 else "png"
            res = client.post(
                upload_url,
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_tok},
                files={"file": (f"doc-{role.value}.{ext}", payload, mime)},
                data={"document_kind": "laudo", "source_label": f"role_{role.value}"},
            )
            assert res.status_code == expected_upload_status[role], (
                f"Role {role.value} expected {expected_upload_status[role]}, got {res.status_code}"
            )
            if res.status_code == 201 and uploaded_doc_id is None:
                uploaded_doc_id = res.json()["document_id"]
                uploaded_ver_id = res.json()["current_version"]["version_id"]

    assert uploaded_doc_id is not None and uploaded_ver_id is not None

    # All 5 active member roles in Org A can list, read metadata, and download content within Org A
    for idx, role in enumerate(OrganizationRole):
        with TestClient(
        app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False
    ) as client:
            _login_bff(
                client,
                idp,
                sub=f"sub-ing-{role.value}",
                email=f"ing.{role.value}@jyxia.local",
                code=f"c-rbac-read-{idx}",
            )
            list_res = client.get(upload_url)
            assert list_res.status_code == 200
            assert list_res.json()["total"] == 2
            assert len(list_res.json()["documents"]) == 2

            meta_res = client.get(
                f"/api/v1/organizations/{ids['org_a_id']}/documents/{uploaded_doc_id}"
            )
            assert meta_res.status_code == 200
            assert meta_res.json()["document_id"] == uploaded_doc_id
            assert len(meta_res.json()["versions"]) == 1

            dl_res = client.get(
                f"/api/v1/organizations/{ids['org_a_id']}/documents/{uploaded_doc_id}/versions/{uploaded_ver_id}/content"
            )
            assert dl_res.status_code == 200
            assert dl_res.content == VALID_SYNTHETIC_PDF
            assert dl_res.headers["x-content-type-options"] == "nosniff"
            assert "attachment;" in dl_res.headers["content-disposition"]
            assert dl_res.headers["x-document-sha256"] == hashlib.sha256(VALID_SYNTHETIC_PDF).hexdigest()

    # Service-layer direct RBAC check (bypassing route dependency) MUST also reject non-upload roles!
    db = factory()
    try:
        for denied_role in (
            OrganizationRole.DOCUMENT_REVIEWER,
            OrganizationRole.AUDITOR_READONLY,
            OrganizationRole.READ_ONLY,
        ):
            with pytest.raises(AuthorizationDeniedError):
                InstitutionalService.ingest_case_document(
                    db,
                    TenantContext(
                        organization_id=ids["org_a_id"],
                        actor_user_id=ids[f"user_{denied_role.value}_id"],
                    ),
                    storage=storage,
                    case_id=ids["case_a_id"],
                    content=VALID_SYNTHETIC_PDF,
                    mime_type="application/pdf",
                    original_filename="service-denied.pdf",
                )
    finally:
        db.close()


def test_document_multitenant_isolation_and_cross_version_blocking(
    migrated_engine, tmp_path: Path
) -> None:
    """13.3: Verify zero cross-tenant upload, metadata listing, or binary content retrieval."""
    idp = MockOidcProviderState()
    storage_dir = tmp_path / "JYXIA_LOCAL_WORK" / "mt_storage"
    settings = _oidc_settings(storage_root=str(storage_dir))
    storage = LocalControlledSyntheticStorage(storage_dir, enabled=True, max_bytes=1024 * 1024)
    factory = create_session_factory(migrated_engine)
    ids = _seed_two_tenants_and_roles(factory, idp.issuer)

    app = create_app(
        settings,
        engine=migrated_engine,
        oidc_adapter=StandardOidcProviderAdapter(settings, transport=idp.transport()),
        storage=storage,
    )

    with (
        TestClient(app, base_url="http://127.0.0.1:8000") as client_a,
        TestClient(app, base_url="http://127.0.0.1:8000") as client_b,
    ):
        _, csrf_a = _login_bff(
            client_a,
            idp,
            sub="sub-ing-org_admin",
            email="ing.org_admin@jyxia.local",
            code="c-mt-a",
        )
        _, csrf_b = _login_bff(
            client_b,
            idp,
            sub="sub-ing-orgb-admin",
            email="ing.orgb.admin@jyxia.local",
            code="c-mt-b",
        )

        # Org A uploads doc_a1 and doc_a2
        res_a1 = client_a.post(
            f"/api/v1/organizations/{ids['org_a_id']}/cases/{ids['case_a_id']}/documents",
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_a},
            files={"file": ("doc-a1.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
        )
        assert res_a1.status_code == 201
        doc_a1_id = res_a1.json()["document_id"]
        ver_a1_id = res_a1.json()["current_version"]["version_id"]

        res_a2 = client_a.post(
            f"/api/v1/organizations/{ids['org_a_id']}/cases/{ids['case_a2_id']}/documents",
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_a},
            files={"file": ("doc-a2.png", VALID_SYNTHETIC_PNG, "image/png")},
        )
        assert res_a2.status_code == 201
        doc_a2_id = res_a2.json()["document_id"]
        ver_a2_id = res_a2.json()["current_version"]["version_id"]

        # Org B uploads doc_b
        res_b = client_b.post(
            f"/api/v1/organizations/{ids['org_b_id']}/cases/{ids['case_b_id']}/documents",
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_b},
            files={"file": ("doc-b.pdf", VALID_SYNTHETIC_PDF_ALT, "application/pdf")},
        )
        assert res_b.status_code == 201
        doc_b_id = res_b.json()["document_id"]
        ver_b_id = res_b.json()["current_version"]["version_id"]

        # 1. Cross-org URL path with Org A session -> 403 Forbidden
        assert (
            client_a.post(
                f"/api/v1/organizations/{ids['org_b_id']}/cases/{ids['case_b_id']}/documents",
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_a},
                files={"file": ("cross.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            ).status_code
            == 403
        )
        # 2. Spoofed X-Organization-ID header -> 403 Forbidden
        assert (
            client_a.post(
                f"/api/v1/organizations/{ids['org_a_id']}/cases/{ids['case_a_id']}/documents",
                headers={
                    "Origin": "http://127.0.0.1:8000",
                    CSRF_HEADER_NAME: csrf_a,
                    "X-Organization-ID": ids["org_b_id"],
                },
                files={"file": ("spoof.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            ).status_code
            == 403
        )
        # 3. Uploading to Org B's case_id under Org A's organization_id -> 404 Not Found
        assert (
            client_a.post(
                f"/api/v1/organizations/{ids['org_a_id']}/cases/{ids['case_b_id']}/documents",
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_a},
                files={"file": ("foreign-case.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            ).status_code
            == 404
        )
        # 4. Listing Org B's case documents from Org A -> 403 (via org_b path) and 404 (via org_a path)
        assert (
            client_a.get(
                f"/api/v1/organizations/{ids['org_b_id']}/cases/{ids['case_b_id']}/documents"
            ).status_code
            == 403
        )
        assert (
            client_a.get(
                f"/api/v1/organizations/{ids['org_a_id']}/cases/{ids['case_b_id']}/documents"
            ).status_code
            == 404
        )
        # 5. Querying Org B's known document UUID from Org A -> 404 (via org_a path) and 403 (via org_b path)
        assert (
            client_a.get(
                f"/api/v1/organizations/{ids['org_a_id']}/documents/{doc_b_id}"
            ).status_code
            == 404
        )
        assert (
            client_a.get(
                f"/api/v1/organizations/{ids['org_b_id']}/documents/{doc_b_id}"
            ).status_code
            == 403
        )
        # 6. Downloading Org B's known document/version UUID from Org A -> 404 / 403
        assert (
            client_a.get(
                f"/api/v1/organizations/{ids['org_a_id']}/documents/{doc_b_id}/versions/{ver_b_id}/content"
            ).status_code
            == 404
        )
        assert (
            client_a.get(
                f"/api/v1/organizations/{ids['org_a_id']}/documents/{doc_a1_id}/versions/{ver_b_id}/content"
            ).status_code
            == 404
        )
        assert (
            client_a.get(
                f"/api/v1/organizations/{ids['org_b_id']}/documents/{doc_b_id}/versions/{ver_b_id}/content"
            ).status_code
            == 403
        )
        # 7. Cross-document version access within the SAME organization (doc_a1 with ver_a2 or doc_a2 with ver_a1) -> 404 Not Found!
        assert (
            client_a.get(
                f"/api/v1/organizations/{ids['org_a_id']}/documents/{doc_a1_id}/versions/{ver_a2_id}/content"
            ).status_code
            == 404
        )
        assert (
            client_a.get(
                f"/api/v1/organizations/{ids['org_a_id']}/documents/{doc_a2_id}/versions/{ver_a1_id}/content"
            ).status_code
            == 404
        )


def test_document_file_validation_streaming_limits_and_failure_compensation(
    migrated_engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """13.4 & 13.5: Verify format/structure validation, streaming size limit, and zero orphan files on DB failure."""
    idp = MockOidcProviderState()
    storage_dir = tmp_path / "JYXIA_LOCAL_WORK" / "val_storage"
    # Configure a small 4096-byte max_document_bytes to test streaming size ceiling enforcement
    settings = _oidc_settings(storage_root=str(storage_dir), max_document_bytes=4096)
    storage = LocalControlledSyntheticStorage(storage_dir, enabled=True, max_bytes=4096)
    factory = create_session_factory(migrated_engine)
    ids = _seed_two_tenants_and_roles(factory, idp.issuer)

    app = create_app(
        settings,
        engine=migrated_engine,
        oidc_adapter=StandardOidcProviderAdapter(settings, transport=idp.transport()),
        storage=storage,
    )
    upload_url = f"/api/v1/organizations/{ids['org_a_id']}/cases/{ids['case_a_id']}/documents"

    with TestClient(
        app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False
    ) as client:
        _, csrf_tok = _login_bff(
            client,
            idp,
            sub="sub-ing-org_admin",
            email="ing.org_admin@jyxia.local",
            code="c-val-1",
        )
        headers = {"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_tok}

        # 1. Valid PDF and valid PNG succeed
        r_pdf = client.post(
            upload_url,
            headers=headers,
            files={"file": ("ok.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
        )
        assert r_pdf.status_code == 201
        r_png = client.post(
            upload_url,
            headers=headers,
            files={"file": ("ok.png", VALID_SYNTHETIC_PNG, "image/png")},
        )
        assert r_png.status_code == 201

        org_storage_dir = storage_dir / ids["org_a_id"]
        committed_files_before = set(org_storage_dir.iterdir())
        assert len(committed_files_before) == 2

        # 2. Unsupported formats, false extensions, and false MIME types -> 415 Unsupported Media Type
        corrupt_crc_png = bytearray(VALID_SYNTHETIC_PNG)
        corrupt_crc_png[-5] ^= 0xFF

        for filename, payload, mime, expected_status in (
            # Empty file
            ("empty.pdf", b"", "application/pdf", 422),
            # Truncated PDF (missing %%EOF)
            ("truncated.pdf", b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n", "application/pdf", 422),
            # PDF with trailing non-whitespace bytes after %%EOF
            ("trailing.pdf", VALID_SYNTHETIC_PDF + b"MALICIOUS_TRAILING_BYTES", "application/pdf", 422),
            # Corrupt PNG CRC-32
            ("bad-crc.png", bytes(corrupt_crc_png), "image/png", 422),
            # Truncated PNG
            ("trunc.png", VALID_SYNTHETIC_PNG[:-6], "image/png", 422),
            # False extension (.png with PDF bytes, .pdf with PNG bytes, .exe with PDF bytes)
            ("spoof.png", VALID_SYNTHETIC_PDF, "application/pdf", 415),
            ("spoof.pdf", VALID_SYNTHETIC_PNG, "image/png", 415),
            ("malware.exe", VALID_SYNTHETIC_PDF, "application/pdf", 415),
            # False MIME type (image/png declared on PDF bytes, application/pdf declared on PNG bytes)
            ("laudo.pdf", VALID_SYNTHETIC_PDF, "image/png", 415),
            ("img.png", VALID_SYNTHETIC_PNG, "application/pdf", 415),
            # Disallowed formats (JPEG, plain text, HTML, ZIP)
            ("photo.jpg", b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00\xff\xd9", "image/jpeg", 415),
            ("notes.txt", b"Plain text synthetic content", "text/plain", 415),
            ("archive.zip", b"PK\x03\x04" + b"\x00" * 30, "application/zip", 415),
            # Oversized payload (> 4096 bytes) -> 413 Content Too Large
            ("huge.pdf", b"%PDF-1.4\n" + (b"0" * 5000) + b"\n%%EOF\n", "application/pdf", 413),
        ):
            res_bad = client.post(
                upload_url,
                headers=headers,
                files={"file": (filename, payload, mime)},
            )
            assert res_bad.status_code == expected_status, (
                f"Case ({filename}, {mime}) expected {expected_status}, got {res_bad.status_code}: {res_bad.text}"
            )

        # 3. Spoofed smaller Content-Length header on an oversized multipart stream MUST still be blocked with 413!
        boundary = "----JyxiaTestBoundary778899"
        oversized_pdf = b"%PDF-1.4\n" + (b"A" * 5000) + b"\n%%EOF\n"
        raw_multipart = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="spoofed-len.pdf"\r\n'
            "Content-Type: application/pdf\r\n\r\n"
        ).encode("utf-8") + oversized_pdf + f"\r\n--{boundary}--\r\n".encode("utf-8")
        res_spoof_len = client.post(
            upload_url,
            content=raw_multipart,
            headers={
                **headers,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Content-Length": "128",
            },
        )
        assert res_spoof_len.status_code == 413

        # 4. Incomplete / interrupted multipart stream (missing closing --boundary--) -> 422
        truncated_multipart = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="file"; filename="incomplete.pdf"\r\n'
            "Content-Type: application/pdf\r\n\r\n"
        ).encode("utf-8") + VALID_SYNTHETIC_PDF
        res_incomplete = client.post(
            upload_url,
            content=truncated_multipart,
            headers={
                **headers,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        assert res_incomplete.status_code == 422

        # 5. Multipart body without 'file' part -> 422
        no_file_multipart = (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="document_kind"\r\n\r\n'
            "laudo\r\n"
            f"--{boundary}--\r\n"
        ).encode("utf-8")
        res_no_file = client.post(
            upload_url,
            content=no_file_multipart,
            headers={
                **headers,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
            },
        )
        assert res_no_file.status_code == 422

        # 6. Path traversal and control characters in filename or metadata fields -> 422
        for bad_filename in ("../escape.pdf", "sub/escape.pdf", "win\\escape.pdf", "ctrl\x07name.pdf"):
            res_trav = client.post(
                upload_url,
                headers=headers,
                files={"file": ("ok.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
                data={"original_filename": bad_filename},
            )
            assert res_trav.status_code == 422

        res_bad_meta = client.post(
            upload_url,
            headers=headers,
            files={"file": ("ok.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            data={"source_label": "bad\x00source"},
        )
        assert res_bad_meta.status_code == 422

        # Confirm zero orphan or temp files were left behind by any of the rejected uploads!
        assert set(org_storage_dir.iterdir()) == committed_files_before

        # 7. Simulated DB/audit failure AFTER physical file write MUST roll back DB and delete the uncommitted file!
        orig_append_event = AuditEventRepository.append_event

        def _failing_append_event(*args, **kwargs):
            if kwargs.get("event_type") == "document.ingested":
                raise RuntimeError("Simulated audit append failure during document ingestion")
            return orig_append_event(*args, **kwargs)

        monkeypatch.setattr(AuditEventRepository, "append_event", _failing_append_event)
        res_db_fail = client.post(
            upload_url,
            headers=headers,
            files={"file": ("rollback-test.pdf", VALID_SYNTHETIC_PDF_ALT, "application/pdf")},
        )
        assert res_db_fail.status_code == 500

        # Physical storage MUST still have ONLY the 2 previously committed files (zero orphan files!)
        assert set(org_storage_dir.iterdir()) == committed_files_before

        # Database MUST still have ONLY the 2 previously committed documents
        db = factory()
        try:
            doc_count = len(
                list(
                    db.scalars(
                        select(Document).where(Document.organization_id == ids["org_a_id"])
                    )
                )
            )
            assert doc_count == 2
        finally:
            db.close()

    # 8. Disabled storage fails closed with 503 Service Unavailable
    disabled_storage = LocalControlledSyntheticStorage(storage_dir, enabled=False, max_bytes=4096)
    app_disabled = create_app(
        settings,
        engine=migrated_engine,
        oidc_adapter=StandardOidcProviderAdapter(settings, transport=idp.transport()),
        storage=disabled_storage,
    )
    with TestClient(app_disabled, base_url="http://127.0.0.1:8000") as dis_client:
        _, csrf_dis = _login_bff(
            dis_client,
            idp,
            sub="sub-ing-org_admin",
            email="ing.org_admin@jyxia.local",
            code="c-val-dis",
        )
        res_503 = dis_client.post(
            upload_url,
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_dis},
            files={"file": ("ok.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
        )
        assert res_503.status_code == 503


def test_document_upload_idempotency_audit_trail_and_version_immutability(
    migrated_engine, tmp_path: Path
) -> None:
    """13.6 & 13.7: Verify Idempotency-Key replay, conflict rejection, audit trail, and version immutability."""
    idp = MockOidcProviderState()
    storage_dir = tmp_path / "JYXIA_LOCAL_WORK" / "idemp_storage"
    settings = _oidc_settings(storage_root=str(storage_dir))
    storage = LocalControlledSyntheticStorage(storage_dir, enabled=True, max_bytes=1024 * 1024)
    factory = create_session_factory(migrated_engine)
    ids = _seed_two_tenants_and_roles(factory, idp.issuer)

    app = create_app(
        settings,
        engine=migrated_engine,
        oidc_adapter=StandardOidcProviderAdapter(settings, transport=idp.transport()),
        storage=storage,
    )
    upload_url = f"/api/v1/organizations/{ids['org_a_id']}/cases/{ids['case_a_id']}/documents"

    with TestClient(
        app, base_url="http://127.0.0.1:8000", raise_server_exceptions=False
    ) as client:
        _, csrf_tok = _login_bff(
            client,
            idp,
            sub="sub-ing-org_admin",
            email="ing.org_admin@jyxia.local",
            code="c-idemp-1",
        )
        base_headers = {"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_tok}

        # 1. First upload with Idempotency-Key -> 201 Created
        res1 = client.post(
            upload_url,
            headers={**base_headers, IDEMPOTENCY_KEY_HEADER_NAME: "idem-upload-key-001"},
            files={"file": ("laudo-idem.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            data={"document_kind": "laudo", "source_label": "idempotent_source"},
        )
        assert res1.status_code == 201
        b1 = res1.json()
        assert b1["idempotent_replay"] is False
        doc1_id = b1["document_id"]
        ver1_id = b1["current_version"]["version_id"]

        org_storage_dir = storage_dir / ids["org_a_id"]
        files_after_first = list(org_storage_dir.iterdir())
        assert len(files_after_first) == 1

        # 2. Retry with SAME Idempotency-Key and SAME file/metadata -> 200 OK with idempotent_replay=True
        res2 = client.post(
            upload_url,
            headers={**base_headers, IDEMPOTENCY_KEY_HEADER_NAME: "idem-upload-key-001"},
            files={"file": ("laudo-idem.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            data={"document_kind": "laudo", "source_label": "idempotent_source"},
        )
        assert res2.status_code == 200
        b2 = res2.json()
        assert b2["idempotent_replay"] is True
        assert b2["document_id"] == doc1_id
        assert b2["current_version"]["version_id"] == ver1_id
        # No second physical file kept on disk!
        assert list(org_storage_dir.iterdir()) == files_after_first

        # 3. Same Idempotency-Key with DIFFERENT file content -> 409 Conflict!
        res_conflict = client.post(
            upload_url,
            headers={**base_headers, IDEMPOTENCY_KEY_HEADER_NAME: "idem-upload-key-001"},
            files={"file": ("laudo-idem.pdf", VALID_SYNTHETIC_PDF_ALT, "application/pdf")},
            data={"document_kind": "laudo", "source_label": "idempotent_source"},
        )
        assert res_conflict.status_code == 409
        assert list(org_storage_dir.iterdir()) == files_after_first

        # 4. Different Idempotency-Key with same content -> independent upload (201 Created)
        res3 = client.post(
            upload_url,
            headers={**base_headers, IDEMPOTENCY_KEY_HEADER_NAME: "idem-upload-key-002"},
            files={"file": ("laudo-idem2.pdf", VALID_SYNTHETIC_PDF, "application/pdf")},
            data={"document_kind": "pedido", "source_label": "idempotent_source_2"},
        )
        assert res3.status_code == 201
        b3 = res3.json()
        assert b3["document_id"] != doc1_id
        assert len(list(org_storage_dir.iterdir())) == 2

        # 5. Pagination on GET .../cases/{case_id}/documents
        page1 = client.get(f"{upload_url}?limit=1&offset=0").json()
        page2 = client.get(f"{upload_url}?limit=1&offset=1").json()
        assert page1["total"] == 2
        assert len(page1["documents"]) == 1
        assert len(page2["documents"]) == 1
        assert page1["documents"][0]["document_id"] == doc1_id
        assert page2["documents"][0]["document_id"] == b3["document_id"]

    # 6. Verify audit events and cryptographic hash chain
    db = factory()
    try:
        ctx_a = TenantContext(organization_id=ids["org_a_id"])
        assert AuditEventRepository.verify_chain(db, ctx_a) is True
        assert SecurityAuditRepository.verify_chain(db) is True

        ingest_events = list(
            db.scalars(
                select(AuditEvent)
                .where(
                    AuditEvent.organization_id == ids["org_a_id"],
                    AuditEvent.event_type == "document.ingested",
                )
                .order_by(AuditEvent.sequence_number.asc())
            )
        )
        # Exactly 2 ingestion audit events (the idempotent replay and the rejected conflict did not add events)
        assert len(ingest_events) == 2
        ev1 = ingest_events[0]
        assert ev1.actor_user_id == ids["user_org_admin_id"]
        assert ev1.target_entity_type == "document"
        assert ev1.target_entity_id == doc1_id
        assert ev1.payload_json["case_id"] == ids["case_a_id"]
        assert ev1.payload_json["document_id"] == doc1_id
        assert ev1.payload_json["document_version_id"] == ver1_id
        assert ev1.payload_json["version_number"] == 1
        assert ev1.payload_json["sha256_hex"] == hashlib.sha256(VALID_SYNTHETIC_PDF).hexdigest()
        assert ev1.payload_json["byte_size"] == len(VALID_SYNTHETIC_PDF)
        assert ev1.payload_json["mime_type"] == "application/pdf"
        # Audit payload MUST NOT contain filename, storage_key, physical paths, or binary content
        serialized_payload = json.dumps(ev1.payload_json)
        assert "laudo-idem.pdf" not in serialized_payload
        assert "storage_key" not in serialized_payload
        assert str(storage_dir) not in serialized_payload

        # 7. DocumentVersion immutability guard blocks overwriting sha256_hex / storage_key or deleting version
        ver_row = db.get(DocumentVersion, ver1_id)
        assert ver_row is not None
        ver_row.sha256_hex = "f" * 64
        with pytest.raises(ValueError, match="immutable"):
            db.flush()
        db.rollback()

        ver_row = db.get(DocumentVersion, ver1_id)
        assert ver_row is not None
        db.delete(ver_row)
        with pytest.raises(ValueError, match="immutable"):
            db.flush()
        db.rollback()
    finally:
        db.close()
