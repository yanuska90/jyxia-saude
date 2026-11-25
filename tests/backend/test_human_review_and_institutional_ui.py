"""Comprehensive backend, security, RBAC, append-only, and re-assessment tests for Etapa 3.3.5."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
import pytest

from app.core.constants import (
    CSRF_HEADER_NAME,
    CaseReadinessState,
    DocumentKind,
    OrganizationRole,
)
from app.core.oidc import StandardOidcProviderAdapter
from app.db.session import create_session_factory
from app.main import create_app
from app.models.entities import HumanReview
from app.repositories.identity import IdentityAndSessionRepository, SecurityAuditRepository
from app.repositories.institutional import (
    AuditEventRepository,
    CaseAndDocumentRepository,
    OrganizationRepository,
)
from app.schemas.tenant import DocumentCaseCreateInput, TenantContext
from app.services.institutional_service import InstitutionalService
from app.services.processing_worker import ProcessingWorker
from app.services.storage import LocalControlledSyntheticStorage
from tests.backend.oidc_test_support import (
    MockOidcProviderState,
    _base_claims,
    _oidc_settings,
    _sign_id_token,
)


def _build_synthetic_selectable_pdf(lines: list[str]) -> bytes:
    """Build a valid multi-line selectable-text PDF 1.4 document with accurate xref offsets."""

    def _esc(s: str) -> str:
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    content_ops = ["BT", "/F1 11 Tf", "50 750 Td"]
    for idx, line in enumerate(lines):
        if idx > 0:
            content_ops.append("0 -22 Td")
        content_ops.append(f"({_esc(line)}) Tj")
    content_ops.append("ET")
    stream_bytes = ("\n".join(content_ops) + "\n").encode("latin-1")

    objs: list[bytes] = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        (
            b"3 0 obj\n"
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>\n"
            b"endobj\n"
        ),
        (
            f"4 0 obj\n<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"endstream\nendobj\n"
        ),
        b"5 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
    ]

    out = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj in objs:
        offsets.append(len(out))
        out.extend(obj)
    xref_pos = len(out)
    out.extend(f"xref\n0 {len(offsets)}\n".encode("ascii"))
    out.extend(b"0000000000 65535 f \n")
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    out.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n".encode(
            "ascii"
        )
    )
    return bytes(out)


def _login_client(
    client: TestClient,
    idp: MockOidcProviderState,
    *,
    subject: str,
    email: str,
    code: str,
) -> str:
    """Execute full OIDC Authorization Code + PKCE + MFA login on TestClient and return CSRF token."""
    login_resp = client.get("/api/v1/auth/login?next=/institutional/", follow_redirects=False)
    assert login_resp.status_code == 302
    parsed = urlparse(login_resp.headers["location"])
    qs = parse_qs(parsed.query)
    state = qs["state"][0]
    nonce = qs["nonce"][0]
    challenge = qs["code_challenge"][0]

    claims = _base_claims(sub=subject, nonce=nonce)
    claims["email"] = email
    id_tok = _sign_id_token(
        idp.rsa_priv,
        alg="RS256",
        kid=idp.rsa_jwk["kid"],
        claims=claims,
    )
    idp.issued_codes[code] = {
        "code_challenge": challenge,
        "id_token": id_tok,
    }
    cb_resp = client.get(
        f"/api/v1/auth/callback?code={code}&state={state}",
        follow_redirects=False,
    )
    assert cb_resp.status_code == 302
    assert cb_resp.headers["location"] == "/institutional/"
    csrf = client.cookies.get("jyxia_csrf")
    assert csrf
    return csrf


def test_human_review_e2e_flow_and_all_mandatory_negative_security_controls(
    migrated_engine, tmp_path: Path
) -> None:
    """Verify full upload -> worker extraction -> 4-axis comparison -> human review -> re-assessment
    plus all 10 mandatory negative security cases and append-only immutability.
    """
    idp = MockOidcProviderState()
    storage_dir = tmp_path / "inst_storage_335"
    settings = _oidc_settings(
        storage_root=str(storage_dir),
        allow_local_synthetic_storage=True,
    )
    storage = LocalControlledSyntheticStorage(
        storage_dir,
        enabled=True,
        max_bytes=settings.max_document_bytes,
    )
    adapter = StandardOidcProviderAdapter(settings, transport=idp.transport())
    factory = create_session_factory(migrated_engine)

    # Seed Org A & Org B and users with distinct roles
    db = factory()
    try:
        org_a = OrganizationRepository.create_organization(
            db, slug="org-rev-a", name="Organizacao Revisao Alpha"
        )
        org_b = OrganizationRepository.create_organization(
            db, slug="org-rev-b", name="Organizacao Revisao Beta"
        )

        users_meta = [
            ("admin_a", "admin.a@jyxia.local", "Admin Alpha", OrganizationRole.ORG_ADMIN, org_a.id),
            (
                "reviewer_a",
                "reviewer.a@jyxia.local",
                "Revisor Documental Alpha",
                OrganizationRole.DOCUMENT_REVIEWER,
                org_a.id,
            ),
            (
                "operator_a",
                "operator.a@jyxia.local",
                "Operador Alpha",
                OrganizationRole.ADMIN_OPERATOR,
                org_a.id,
            ),
            (
                "auditor_a",
                "auditor.a@jyxia.local",
                "Auditor Alpha",
                OrganizationRole.AUDITOR_READONLY,
                org_a.id,
            ),
            (
                "readonly_a",
                "readonly.a@jyxia.local",
                "Leitor Alpha",
                OrganizationRole.READ_ONLY,
                org_a.id,
            ),
            (
                "admin_b",
                "admin.b@jyxia.local",
                "Admin Beta",
                OrganizationRole.ORG_ADMIN,
                org_b.id,
            ),
        ]
        user_ids: dict[str, str] = {}
        for sub_key, email, name, role, target_org_id in users_meta:
            u = OrganizationRepository.create_user(
                db, email=email, display_name=name, mfa_enrolled=True
            )
            OrganizationRepository.assign_membership(
                db,
                TenantContext(organization_id=target_org_id),
                user_id=u.id,
                role=role.value,
            )
            IdentityAndSessionRepository.bind_external_identity(
                db,
                user_id=u.id,
                issuer=idp.issuer,
                subject=f"sub-{sub_key}",
                email_at_binding=email,
            )
            user_ids[sub_key] = u.id

        # Also create a case in Org B to test cross-tenant isolation
        case_b = InstitutionalService.create_case(
            db,
            TenantContext(organization_id=org_b.id, actor_user_id=user_ids["admin_b"]),
            DocumentCaseCreateInput(case_code="CASO-ORG-B-01"),
        )
        ing_b = InstitutionalService.ingest_case_document(
            db,
            TenantContext(organization_id=org_b.id, actor_user_id=user_ids["admin_b"]),
            storage=storage,
            case_id=case_b.id,
            content=_build_synthetic_selectable_pdf(
                [
                    "Tipo: solicitacao",
                    "Paciente: Paciente Sintetico Beta",
                    "Nascimento: 1980-04-10",
                    "Identificador: CPF-SYN-999",
                    "Emissao: 2026-10-01",
                    "Procedimento: Facoemulsificacao",
                    "Sistema: TUSS",
                    "Codigo: 31309054",
                    "Lateralidade: OD",
                ]
            ),
            mime_type="application/pdf",
            original_filename="pedido-org-b.pdf",
            document_kind=DocumentKind.PEDIDO,
            source_label="Pedido Org B",
        )
        db.commit()
        org_a_id = org_a.id
        org_b_id = org_b.id
        doc_b_id = ing_b.document.id
        ver_b_id = ing_b.version.id
    finally:
        db.close()

    app = create_app(settings, engine=migrated_engine, oidc_adapter=adapter, storage=storage)
    worker = ProcessingWorker(factory, storage, settings, worker_id="test-worker-335")

    # 1. Verify same-origin institutional UI static routes & security headers
    with TestClient(app, base_url="http://127.0.0.1:8000") as anon_client:
        ui_resp = anon_client.get("/institutional/")
        assert ui_resp.status_code == 200
        assert "JYXIA" in ui_resp.text
        assert "no-store" in ui_resp.headers["cache-control"]
        assert "script-src 'self'" in ui_resp.headers["content-security-policy"]
        assert ui_resp.headers["x-content-type-options"] == "nosniff"

        for asset in (
            "/institutional/institutional.css",
            "/institutional/institutional-core.mjs",
            "/institutional/institutional-ui.mjs",
            "/institutional/vendor/pdf.min.mjs",
            "/institutional/vendor/pdf.worker.min.mjs",
            "/institutional/assets/favicon.svg",
        ):
            r_asset = anon_client.get(asset)
            assert r_asset.status_code == 200, f"Failed to serve {asset}"
            assert "no-store" in r_asset.headers["cache-control"]

        # Unallowed traversal or lab file must return 404
        assert anon_client.get("/institutional/../lab/lab-local.html").status_code == 404
        assert anon_client.get("/institutional/nonexistent.js").status_code == 404

        # Negative Test 1: Unauthenticated user cannot list or create human reviews (401)
        assert (
            anon_client.get(
                f"/api/v1/organizations/{org_a_id}/documents/{doc_b_id}/versions/{ver_b_id}/human-reviews"
            ).status_code
            == 401
        )
        assert (
            anon_client.post(
                f"/api/v1/organizations/{org_a_id}/documents/{doc_b_id}/versions/{ver_b_id}/human-reviews",
                json={"action_type": "observed", "justification": "Tentativa sem sessao"},
            ).status_code
            == 401
        )

    # 2. Authenticate Admin Alpha & create Scenario A (Coherent 2-document case) via API
    with TestClient(app, base_url="http://127.0.0.1:8000") as admin_client:
        admin_csrf = _login_client(
            admin_client,
            idp,
            subject="sub-admin_a",
            email="admin.a@jyxia.local",
            code="code-admin-a",
        )
        mut_headers = {
            CSRF_HEADER_NAME: admin_csrf,
            "Origin": "http://127.0.0.1:8000",
        }

        create_case_resp = admin_client.post(
            f"/api/v1/organizations/{org_a_id}/cases",
            headers=mut_headers,
            json={
                "case_code": "CASO-335-COERENTE-A",
                "procedure_reference": "TUSS:31309054",
                "external_reference": "GUIA-335-A",
                "declared_laterality": "OD",
            },
        )
        assert create_case_resp.status_code == 201
        case_a_data = create_case_resp.json()
        case_a_id = case_a_data["case_id"]
        assert case_a_data["readiness_state"] == CaseReadinessState.PENDENTE.value
        assert case_a_data["clinical_approval"] is False
        assert case_a_data["administrative_only"] is True

        # Duplicate case_code rejected with 409
        dup_case_resp = admin_client.post(
            f"/api/v1/organizations/{org_a_id}/cases",
            headers=mut_headers,
            json={"case_code": "CASO-335-COERENTE-A"},
        )
        assert dup_case_resp.status_code == 409

        # Upload Document 1 (Solicitacao) & Document 2 (Laudo) with coherent 4-axis fields
        pdf_doc_1 = _build_synthetic_selectable_pdf(
            [
                "Tipo: solicitacao",
                "Subfamilia: oftalmologia",
                "Origem: Ambulatorio Sintetico Alpha",
                "Paciente: Helena Sintetica Oliveira",
                "Nascimento: 1975-08-14",
                "Identificador: CPF-SYN-335-01",
                "Emissao: 2026-10-10",
                "Procedimento: Facoemulsificacao com implante de lente intraocular",
                "Sistema: TUSS",
                "Codigo: 31309054",
                "Lateralidade: OD",
            ]
        )
        pdf_doc_2 = _build_synthetic_selectable_pdf(
            [
                "Tipo: laudo",
                "Subfamilia: oftalmologia",
                "Origem: Centro Diagnostico Sintetico Alpha",
                "Paciente: Helena Sintetica Oliveira",
                "Nascimento: 1975-08-14",
                "Identificador: CPF-SYN-335-01",
                "Emissao: 2026-10-12",
                "Procedimento: Facoemulsificacao com implante de lente intraocular",
                "Sistema: TUSS",
                "Codigo: 31309054",
                "Lateralidade: Olho Direito (OD)",
            ]
        )

        up1 = admin_client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=mut_headers,
            data={"document_kind": "pedido", "source_label": "Solicitacao Medica A"},
            files={"file": ("solicitacao-a.pdf", pdf_doc_1, "application/pdf")},
        )
        assert up1.status_code == 201
        doc1_id = up1.json()["document_id"]
        ver1_id = up1.json()["current_version"]["version_id"]

        up2 = admin_client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
            headers=mut_headers,
            data={"document_kind": "laudo", "source_label": "Laudo Biometria B"},
            files={"file": ("laudo-b.pdf", pdf_doc_2, "application/pdf")},
        )
        assert up2.status_code == 201
        doc2_id = up2.json()["document_id"]
        ver2_id = up2.json()["current_version"]["version_id"]

        # Drain worker queue: 2 integrity + 2 extract + 1 barrier compare_consistency
        for _ in range(4):
            stats = worker.process_one_cycle(max_jobs=10)
            if stats.claimed == 0:
                break

        # Inspect Assessment #1 before human review: all 4 axes are OK, but readiness_state MUST be PENDENTE
        assessments_resp = admin_client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/consistency-assessments"
        )
        assert assessments_resp.status_code == 200
        assessments_list = assessments_resp.json()["assessments"]
        assert len(assessments_list) == 1
        assess_1 = assessments_list[0]
        assert assess_1["assessment_sequence"] == 1
        assert assess_1["automated_axes_outcome"] == "all_ok"
        assert assess_1["human_review_completed"] is False
        assert assess_1["readiness_state"] == CaseReadinessState.PENDENTE.value
        assert "AWAITING_HUMAN_ADMINISTRATIVE_REVIEW" in assess_1["limitations"]

        # Count extract runs so we can prove post-review re-assessment does NOT re-run PDF extraction
        runs_before_review = admin_client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs"
        ).json()["processing_runs"]
        extract_runs_before = [
            r for r in runs_before_review if r["step_type"] == "extract_pdf_text"
        ]
        assert len(extract_runs_before) == 2

    # 3. Negative Security Tests (CSRF, RBAC roles without field:review, Cross-Tenant, Payload Forgery)
    # 3a. Negative Test 2: Missing or invalid CSRF token on POST human-reviews -> 403
    with TestClient(app, base_url="http://127.0.0.1:8000") as reviewer_client:
        reviewer_csrf = _login_client(
            reviewer_client,
            idp,
            subject="sub-reviewer_a",
            email="reviewer.a@jyxia.local",
            code="code-reviewer-a",
        )
        rev_headers = {
            CSRF_HEADER_NAME: reviewer_csrf,
            "Origin": "http://127.0.0.1:8000",
        }

        no_csrf_resp = reviewer_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver1_id}/human-reviews",
            headers={"Origin": "http://127.0.0.1:8000"},
            json={
                "action_type": "observed",
                "justification": "Tentativa sem token CSRF valido.",
            },
        )
        assert no_csrf_resp.status_code == 403

        bad_csrf_resp = reviewer_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver1_id}/human-reviews",
            headers={
                CSRF_HEADER_NAME: "forged-csrf-token-value",
                "Origin": "http://127.0.0.1:8000",
            },
            json={
                "action_type": "observed",
                "justification": "Tentativa com token CSRF forjado.",
            },
        )
        assert bad_csrf_resp.status_code == 403

        # 3b. Negative Test 4: Cross-tenant attempt (Reviewer in Org A targeting Org B or Org B doc in Org A URL)
        cross_org_url_resp = reviewer_client.post(
            f"/api/v1/organizations/{org_b_id}/documents/{doc_b_id}/versions/{ver_b_id}/human-reviews",
            headers=rev_headers,
            json={
                "action_type": "observed",
                "justification": "Tentativa cross-tenant para Org B.",
            },
        )
        assert cross_org_url_resp.status_code == 403

        cross_doc_in_org_a_resp = reviewer_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_b_id}/versions/{ver_b_id}/human-reviews",
            headers=rev_headers,
            json={
                "action_type": "observed",
                "justification": "Tentativa de revisar documento de outra organizacao.",
            },
        )
        assert cross_doc_in_org_a_resp.status_code == 404

        # 3c. Negative Test 5: Version that does not belong to target document -> 404
        mismatched_ver_resp = reviewer_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver2_id}/human-reviews",
            headers=rev_headers,
            json={
                "action_type": "observed",
                "justification": "Versao pertence ao doc2 e nao ao doc1.",
            },
        )
        assert mismatched_ver_resp.status_code == 404

        # 3d. Negative Test 8 & 9: Attempt to forge reviewer_user_id, readiness_state, clinical_approval, or axis status -> 422
        for forbidden_payload in (
            {
                "action_type": "observed",
                "justification": "Tentativa de forjar reviewer_user_id no payload.",
                "reviewer_user_id": user_ids["admin_a"],
            },
            {
                "action_type": "observed",
                "justification": "Tentativa de forcar readiness_state conferida.",
                "readiness_state": "conferida",
            },
            {
                "action_type": "observed",
                "justification": "Tentativa de forcar clinical_approval true.",
                "clinical_approval": True,
            },
            {
                "action_type": "observed",
                "justification": "Tentativa de sobrescrever eixo lateralidade.",
                "axes_override": {"lateralidade": "ok"},
            },
            {
                "action_type": "observed",
                "justification": "curto",  # 5 chars is min; test < 5 chars below
            },
        ):
            if forbidden_payload.get("justification") == "curto":
                continue
            forged_resp = reviewer_client.post(
                f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver1_id}/human-reviews",
                headers=rev_headers,
                json=forbidden_payload,
            )
            assert forged_resp.status_code == 422, f"Expected 422 for {forbidden_payload}"

        # Justification shorter than 5 chars -> 422
        short_just_resp = reviewer_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver1_id}/human-reviews",
            headers=rev_headers,
            json={"action_type": "observed", "justification": "abc"},
        )
        assert short_just_resp.status_code == 422

    # 3e. Negative Test 3: Roles without field:review (admin_operator, auditor_readonly, read_only) MUST get 403 on POST,
    #     while still being allowed to GET human reviews (document:read).
    for role_key in ("operator_a", "auditor_a", "readonly_a"):
        with TestClient(app, base_url="http://127.0.0.1:8000") as role_client:
            r_csrf = _login_client(
                role_client,
                idp,
                subject=f"sub-{role_key}",
                email=f"{role_key.replace('_a', '.a')}@jyxia.local",
                code=f"code-{role_key}",
            )
            r_headers = {
                CSRF_HEADER_NAME: r_csrf,
                "Origin": "http://127.0.0.1:8000",
            }
            denied_post = role_client.post(
                f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver1_id}/human-reviews",
                headers=r_headers,
                json={
                    "action_type": "observed",
                    "justification": f"Tentativa pelo papel {role_key} sem permissao field:review.",
                },
            )
            assert denied_post.status_code == 403, f"Role {role_key} must be denied field:review"

            allowed_get = role_client.get(
                f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/human-reviews"
            )
            assert allowed_get.status_code == 200

    # 4. Positive Administrative Human Review Flow by document_reviewer on Scenario A
    with TestClient(app, base_url="http://127.0.0.1:8000") as reviewer_client:
        reviewer_csrf = _login_client(
            reviewer_client,
            idp,
            subject="sub-reviewer_a",
            email="reviewer.a@jyxia.local",
            code="code-reviewer-a-pos",
        )
        rev_headers = {
            CSRF_HEADER_NAME: reviewer_csrf,
            "Origin": "http://127.0.0.1:8000",
        }

        # Record review on Document 1 Version 1
        rev1_resp = reviewer_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver1_id}/human-reviews",
            headers=rev_headers,
            json={
                "action_type": "observed",
                "justification": "Conferencia administrativa da Solicitacao Medica v1 realizada.",
            },
        )
        assert rev1_resp.status_code == 201
        rev1_body = rev1_resp.json()
        assert rev1_body["reviewer_user_id"] == user_ids["reviewer_a"]
        assert rev1_body["reviewer_role"] == OrganizationRole.DOCUMENT_REVIEWER.value
        assert rev1_body["document_version_id"] == ver1_id
        assert rev1_body["idempotent_replay"] is False
        assert rev1_body["comparison_processing_run"] is not None
        assert rev1_body["clinical_approval"] is False
        assert rev1_body["administrative_only"] is True

        # Idempotent replay of general version review returns 200 without duplicating row
        rev1_dup_resp = reviewer_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver1_id}/human-reviews",
            headers=rev_headers,
            json={
                "action_type": "observed",
                "justification": "Segundo envio repetido para a mesma versao.",
            },
        )
        assert rev1_dup_resp.status_code == 200
        assert rev1_dup_resp.json()["idempotent_replay"] is True
        assert rev1_dup_resp.json()["review_id"] == rev1_body["review_id"]

        # Worker runs queued comparison after 1st review -> still PENDENTE because Doc 2 is unreviewed
        worker.process_one_cycle(max_jobs=5)
        case_mid = reviewer_client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}"
        ).json()
        assert case_mid["reviewed_active_versions_count"] == 1
        assert case_mid["active_versions_count"] == 2
        assert case_mid["human_review_completed"] is False
        assert case_mid["readiness_state"] == CaseReadinessState.PENDENTE.value

        # Record review on Document 2 Version 1
        rev2_resp = reviewer_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc2_id}/versions/{ver2_id}/human-reviews",
            headers=rev_headers,
            json={
                "action_type": "observed",
                "justification": "Conferencia administrativa do Laudo Biometria v1 concluida.",
            },
        )
        assert rev2_resp.status_code == 201
        assert rev2_resp.json()["comparison_processing_run"] is not None

        # Worker executes compare_consistency -> Case A transitions to CONFERIDA!
        worker.process_one_cycle(max_jobs=5)

        case_final = reviewer_client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}"
        ).json()
        assert case_final["reviewed_active_versions_count"] == 2
        assert case_final["human_review_completed"] is True
        assert case_final["readiness_state"] == CaseReadinessState.CONFERIDA.value
        assert case_final["clinical_approval"] is False
        assert case_final["administrative_only"] is True

        # Verify historical assessments are preserved append-only (sequences 1, 2, 3)
        hist_resp = reviewer_client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/consistency-assessments"
        ).json()
        assert hist_resp["total"] == 3
        seqs = [a["assessment_sequence"] for a in hist_resp["assessments"]]
        assert seqs == [3, 2, 1]
        assert hist_resp["assessments"][0]["readiness_state"] == CaseReadinessState.CONFERIDA.value
        assert hist_resp["assessments"][0]["human_review_completed"] is True
        assert hist_resp["assessments"][2]["readiness_state"] == CaseReadinessState.PENDENTE.value
        assert hist_resp["assessments"][2]["human_review_completed"] is False

        # Verify PDF text extraction was NOT repeated during post-review re-evaluations
        runs_after_review = reviewer_client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs"
        ).json()["processing_runs"]
        extract_runs_after = [
            r for r in runs_after_review if r["step_type"] == "extract_pdf_text"
        ]
        assert len(extract_runs_after) == 2

    # 5. Scenario B: Conflicting documents (OD vs OE) MUST remain BLOQUEADO even after full human review!
    with TestClient(app, base_url="http://127.0.0.1:8000") as admin_client:
        admin_csrf = _login_client(
            admin_client,
            idp,
            subject="sub-admin_a",
            email="admin.a@jyxia.local",
            code="code-admin-a-conflict",
        )
        mut_headers = {
            CSRF_HEADER_NAME: admin_csrf,
            "Origin": "http://127.0.0.1:8000",
        }

        conflict_case = admin_client.post(
            f"/api/v1/organizations/{org_a_id}/cases",
            headers=mut_headers,
            json={
                "case_code": "CASO-335-CONFLITO-B",
                "procedure_reference": "TUSS:31309054",
            },
        ).json()
        conflict_case_id = conflict_case["case_id"]

        pdf_od = _build_synthetic_selectable_pdf(
            [
                "Tipo: solicitacao",
                "Paciente: Marcos Sintetico Souza",
                "Nascimento: 1968-02-20",
                "Identificador: CPF-SYN-335-02",
                "Emissao: 2026-10-15",
                "Procedimento: Facoemulsificacao",
                "Sistema: TUSS",
                "Codigo: 31309054",
                "Lateralidade: OD",
            ]
        )
        pdf_oe = _build_synthetic_selectable_pdf(
            [
                "Tipo: laudo",
                "Paciente: Marcos Sintetico Souza",
                "Nascimento: 1968-02-20",
                "Identificador: CPF-SYN-335-02",
                "Emissao: 2026-10-15",
                "Procedimento: Facoemulsificacao",
                "Sistema: TUSS",
                "Codigo: 31309054",
                "Lateralidade: OE",
            ]
        )

        c_up1 = admin_client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{conflict_case_id}/documents",
            headers=mut_headers,
            data={"document_kind": "pedido", "source_label": "Solicitacao OD"},
            files={"file": ("solicitacao-od.pdf", pdf_od, "application/pdf")},
        ).json()
        c_up2 = admin_client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{conflict_case_id}/documents",
            headers=mut_headers,
            data={"document_kind": "laudo", "source_label": "Laudo OE Divergente"},
            files={"file": ("laudo-oe.pdf", pdf_oe, "application/pdf")},
        ).json()

        for _ in range(4):
            st = worker.process_one_cycle(max_jobs=10)
            if st.claimed == 0:
                break

        # Record administrative human review on BOTH versions of the conflicting case
        for d_id, v_id in (
            (c_up1["document_id"], c_up1["current_version"]["version_id"]),
            (c_up2["document_id"], c_up2["current_version"]["version_id"]),
        ):
            r_rev = admin_client.post(
                f"/api/v1/organizations/{org_a_id}/documents/{d_id}/versions/{v_id}/human-reviews",
                headers=mut_headers,
                json={
                    "action_type": "observed",
                    "justification": "Conferencia administrativa registrada em documento com conflito OD/OE.",
                },
            )
            assert r_rev.status_code == 201

        worker.process_one_cycle(max_jobs=10)

        conflict_after = admin_client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{conflict_case_id}"
        ).json()
        assert conflict_after["human_review_completed"] is True
        assert conflict_after["readiness_state"] == CaseReadinessState.BLOQUEADO.value
        assert conflict_after["has_conflict"] is True
        assert conflict_after["clinical_approval"] is False

    # 6. Negative Tests 6, 7 & 10: Superseded version, Discarded document, and Direct ORM UPDATE/DELETE on HumanReview
    db2 = factory()
    try:
        # Supersede ver1_id on doc1_id with a v2
        ver2_new = InstitutionalService.store_and_register_document_version(
            db2,
            TenantContext(organization_id=org_a_id, actor_user_id=user_ids["admin_a"]),
            storage=storage,
            document_id=doc1_id,
            version_number=2,
            content=pdf_doc_1,
            mime_type="application/pdf",
            original_filename="solicitacao-a-v2.pdf",
            enqueue_processing=False,
        )
        ver1_row = CaseAndDocumentRepository.get_document_version(
            db2, TenantContext(organization_id=org_a_id), ver1_id
        )
        assert ver1_row is not None
        ver1_row.is_current = False
        ver1_row.superseded_by_version_id = ver2_new.id
        db2.commit()
        superseded_ver_id = ver1_id
    finally:
        db2.close()

    with TestClient(app, base_url="http://127.0.0.1:8000") as admin_client:
        admin_csrf = _login_client(
            admin_client,
            idp,
            subject="sub-admin_a",
            email="admin.a@jyxia.local",
            code="code-admin-a-neg67",
        )
        mut_headers = {
            CSRF_HEADER_NAME: admin_csrf,
            "Origin": "http://127.0.0.1:8000",
        }

        # Negative Test 6: Review on superseded version -> 409 Conflict
        sup_resp = admin_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{superseded_ver_id}/human-reviews",
            headers=mut_headers,
            json={
                "action_type": "observed",
                "field_key": "patient",
                "justification": "Tentativa em versao substituida.",
            },
        )
        assert sup_resp.status_code == 409

    # Discard doc2_id and verify review on discarded document is rejected with 409
    db3 = factory()
    try:
        doc2_row = CaseAndDocumentRepository.get_document(
            db3, TenantContext(organization_id=org_a_id), doc2_id
        )
        assert doc2_row is not None
        from app.db.base import utc_now

        doc2_row.discarded_at = utc_now()
        doc2_row.discarded_by_user_id = user_ids["admin_a"]
        doc2_row.discard_reason = "Documento descartado em teste de seguranca."
        db3.commit()
    finally:
        db3.close()

    with TestClient(app, base_url="http://127.0.0.1:8000") as admin_client:
        admin_csrf = _login_client(
            admin_client,
            idp,
            subject="sub-admin_a",
            email="admin.a@jyxia.local",
            code="code-admin-a-discard",
        )
        mut_headers = {
            CSRF_HEADER_NAME: admin_csrf,
            "Origin": "http://127.0.0.1:8000",
        }

        # Negative Test 7: Review on discarded document -> 409 Conflict
        disc_resp = admin_client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc2_id}/versions/{ver2_id}/human-reviews",
            headers=mut_headers,
            json={
                "action_type": "observed",
                "field_key": "patient",
                "justification": "Tentativa em documento descartado.",
            },
        )
        assert disc_resp.status_code == 409

        # Also verify no PUT / PATCH / DELETE endpoints exist on human-reviews (405 Method Not Allowed)
        assert (
            admin_client.delete(
                f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver1_id}/human-reviews",
                headers=mut_headers,
            ).status_code
            == 405
        )
        assert (
            admin_client.put(
                f"/api/v1/organizations/{org_a_id}/documents/{doc1_id}/versions/{ver1_id}/human-reviews",
                headers=mut_headers,
                json={},
            ).status_code
            == 405
        )

    # Negative Test 10: Direct ORM mutation or deletion of an existing HumanReview record MUST raise ValueError
    db4 = factory()
    try:
        existing_review = db4.query(HumanReview).first()
        assert existing_review is not None
        existing_review.justification = "Tentativa de adulterar revisao existente."
        with pytest.raises(ValueError, match="strictly append-only and cannot be updated"):
            db4.flush()
        db4.rollback()

        existing_review = db4.query(HumanReview).first()
        assert existing_review is not None
        db4.delete(existing_review)
        with pytest.raises(ValueError, match="strictly append-only and cannot be deleted"):
            db4.flush()
        db4.rollback()

        # Verify audit hash chain integrity across all organizations
        assert AuditEventRepository.verify_chain(db4, TenantContext(organization_id=org_a_id))
        assert AuditEventRepository.verify_chain(db4, TenantContext(organization_id=org_b_id))
        assert SecurityAuditRepository.verify_chain(db4)
    finally:
        db4.close()
