"""Comprehensive tests for Etapa 3.3.3 deterministic PDF extraction, spatial evidence and abstention."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError

from app.core.config import Settings
from app.core.constants import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CaseReadinessState,
    DocumentKind,
    ExtractedFieldStatus,
    OrganizationRole,
    ProcessingStatus,
    ProcessingStepType,
    SESSION_COOKIE_NAME,
)
from app.core.logging import LOGGER_NAME as APP_LOGGER_NAME
from app.core.session_crypto import hmac_token_digest
from app.db.base import new_uuid, utc_now
from app.db.session import (
    apply_pg_rls_context,
    clear_pg_rls_context,
    create_session_factory,
)
from app.models.entities import EvidenceReference, ExtractedField
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
from app.services.pdf_extraction import (
    PdfExtractionError,
    PdfExtractionLimits,
    extract_pdf_document,
    normalize_ltpage_bbox_to_viewport,
    InvalidBoundingBoxError,
)
from app.services.processing_worker import ProcessingWorker
from app.services.storage import LocalControlledSyntheticStorage

from app.main import create_app

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "frontend" / "public" / "fixtures"


def _pdf_escape(text_str: str) -> bytes:
    """Encode Latin-1 / WinAnsi text safely inside a PDF literal string."""
    raw = text_str.encode("latin-1", errors="replace")
    out = bytearray()
    for b in raw:
        if b in (ord("\\"), ord("("), ord(")")):
            out.append(ord("\\"))
        out.append(b)
    return bytes(out)


def _build_synthetic_pdf(
    pages: list[dict[str, Any]],
    *,
    encrypted: bool = False,
) -> bytes:
    """Build valid multi-page synthetic PDF with WinAnsi Helvetica text, rotations, CropBox & images."""
    objects: list[bytes] = []

    def add_obj(body: bytes) -> int:
        objects.append(body)
        return len(objects)

    catalog_idx = add_obj(b"")
    pages_idx = add_obj(b"")
    font_idx = add_obj(
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>"
    )
    img_xobj_idx = add_obj(
        b"<< /Type /XObject /Subtype /Image /Width 2 /Height 2 "
        b"/ColorSpace /DeviceGray /BitsPerComponent 8 /Length 4 >>\n"
        b"stream\n\xff\x00\x00\xff\nendstream"
    )

    page_refs: list[int] = []
    for pg in pages:
        mediabox = pg.get("mediabox", (0, 0, 595, 842))
        cropbox = pg.get("cropbox")
        rotate = int(pg.get("rotate", 0))
        lines = pg.get("lines", [])  # list of (x, y, text) or (x, y, text, font_size)
        raw_stream = pg.get("raw_stream")
        has_image = bool(pg.get("image_only", False) or pg.get("has_image", False))

        if raw_stream is not None:
            stream_bytes = raw_stream if isinstance(raw_stream, bytes) else raw_stream.encode("latin-1")
        else:
            parts: list[bytes] = []
            if has_image:
                parts.append(b"q 200 0 0 200 50 400 cm /Im1 Do Q")
            if lines:
                parts.append(b"BT")
                for entry in lines:
                    if len(entry) == 4:
                        lx, ly, txt, fsize = entry
                    else:
                        lx, ly, txt = entry
                        fsize = 12
                    parts.append(
                        f"/F1 {fsize} Tf 1 0 0 1 {lx} {ly} Tm (".encode("ascii")
                        + _pdf_escape(txt)
                        + b") Tj"
                    )
                parts.append(b"ET")
            stream_bytes = b"\n".join(parts)

        content_idx = add_obj(
            f"<< /Length {len(stream_bytes)} >>\nstream\n".encode("ascii")
            + stream_bytes
            + b"\nendstream"
        )
        mb_str = f"[{mediabox[0]} {mediabox[1]} {mediabox[2]} {mediabox[3]}]"
        cb_str = (
            f" /CropBox [{cropbox[0]} {cropbox[1]} {cropbox[2]} {cropbox[3]}]"
            if cropbox is not None
            else ""
        )
        rot_str = f" /Rotate {rotate}" if rotate else ""
        page_dict = (
            f"<< /Type /Page /Parent {pages_idx} 0 R /MediaBox {mb_str}{cb_str}{rot_str} "
            f"/Resources << /Font << /F1 {font_idx} 0 R >> /XObject << /Im1 {img_xobj_idx} 0 R >> >> "
            f"/Contents {content_idx} 0 R >>"
        ).encode("ascii")
        page_refs.append(add_obj(page_dict))

    encrypt_idx: int | None = None
    if encrypted:
        encrypt_idx = add_obj(
            b"<< /Filter /Standard /V 1 /R 2 /O <0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20> "
            b"/U <0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20> /P -4 >>"
        )

    objects[catalog_idx - 1] = f"<< /Type /Catalog /Pages {pages_idx} 0 R >>".encode("ascii")
    kids_str = " ".join(f"{pid} 0 R" for pid in page_refs)
    objects[pages_idx - 1] = (
        f"<< /Type /Pages /Kids [{kids_str}] /Count {len(page_refs)} >>".encode("ascii")
    )

    out = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for idx, body in enumerate(objects, start=1):
        offsets.append(len(out))
        out.extend(f"{idx} 0 obj\n".encode("ascii"))
        out.extend(body)
        out.extend(b"\nendobj\n")

    xref_pos = len(out)
    out.extend(f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode("ascii"))
    for off in offsets[1:]:
        out.extend(f"{off:010d} 00000 n \n".encode("ascii"))
    enc_entry = f" /Encrypt {encrypt_idx} 0 R /ID [<01> <01>]" if encrypt_idx is not None else ""
    out.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root {catalog_idx} 0 R{enc_entry} >>\n"
        f"startxref\n{xref_pos}\n%%EOF\n".encode("ascii")
    )
    return bytes(out)


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


def _render_url(engine) -> str:
    return engine.url.render_as_string(hide_password=False)


def _seed_workspace(migrated_engine, app_engine, tmp_path: Path) -> dict[str, Any]:
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
    )
    owner_factory = create_session_factory(migrated_engine)
    db = owner_factory()
    try:
        org_a = OrganizationRepository.create_organization(db, slug="ext-org-a", name="Extract Org A")
        org_b = OrganizationRepository.create_organization(db, slug="ext-org-b", name="Extract Org B")
        actors: dict[str, dict[str, Any]] = {}
        for key, role_val, org_id in (
            ("admin", OrganizationRole.ORG_ADMIN.value, org_a.id),
            ("operator", OrganizationRole.ADMIN_OPERATOR.value, org_a.id),
            ("reviewer", OrganizationRole.DOCUMENT_REVIEWER.value, org_a.id),
            ("readonly", OrganizationRole.READ_ONLY.value, org_a.id),
            ("org_b_admin", OrganizationRole.ORG_ADMIN.value, org_b.id),
        ):
            user = OrganizationRepository.create_user(
                db,
                email=f"{key}.{new_uuid()[:6]}@jyxia.local",
                display_name=f"User {key}",
                mfa_enrolled=True,
            )
            OrganizationRepository.assign_membership(
                db, TenantContext(organization_id=org_id), user_id=user.id, role=role_val
            )
            ext = IdentityAndSessionRepository.bind_external_identity(
                db,
                user_id=user.id,
                issuer="https://idp.jyxia.local/realms/extract",
                subject=f"sub-{key}-{new_uuid()[:8]}",
                email_at_binding=user.email,
            )
            raw_session = f"sess_{key}_{new_uuid()}"
            raw_csrf = f"csrf_{key}_{new_uuid()}"
            now = utc_now()
            IdentityAndSessionRepository.create_auth_session(
                db,
                user_id=user.id,
                external_identity_id=ext.id,
                active_organization_id=org_id,
                session_token_hash=hmac_token_digest(
                    raw_session, secret=settings.session_secret, context="session_token"
                ),
                csrf_token_hash=hmac_token_digest(
                    raw_csrf, secret=settings.csrf_secret, context="csrf_token"
                ),
                auth_method="oidc_pkce_mfa",
                acr="urn:jyxia:loa:mfa",
                amr_json=["pwd", "otp"],
                mfa_verified_at=now,
                oidc_auth_time=now,
                idle_expires_at=now + timedelta(minutes=30),
                absolute_expires_at=now + timedelta(hours=8),
                now=now,
            )
            actors[key] = {
                "user_id": user.id,
                "organization_id": org_id,
                "role": role_val,
                "session_cookie": raw_session,
                "csrf_cookie": raw_csrf,
            }

        case_a = CaseAndDocumentRepository.create_case(
            db,
            TenantContext(organization_id=org_a.id, actor_user_id=actors["admin"]["user_id"]),
            case_code="EXT-CASE-A1",
            external_reference=None,
            procedure_reference="Extracao deterministica A",
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        case_b = CaseAndDocumentRepository.create_case(
            db,
            TenantContext(organization_id=org_b.id, actor_user_id=actors["org_b_admin"]["user_id"]),
            case_code="EXT-CASE-B1",
            external_reference=None,
            procedure_reference="Extracao deterministica B",
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


def _upload_and_process(
    app,
    worker_engine,
    settings: Settings,
    storage_root: Path,
    *,
    org_id: str,
    case_id: str,
    actor: dict[str, Any],
    filename: str,
    payload: bytes,
    mime_type: str,
    document_kind: DocumentKind = DocumentKind.LAUDO,
    max_jobs: int = 10,
) -> tuple[dict[str, Any], Any]:
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, actor["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, actor["csrf_cookie"])
        resp = client.post(
            f"/api/v1/organizations/{org_id}/cases/{case_id}/documents",
            headers={
                CSRF_HEADER_NAME: actor["csrf_cookie"],
                "Origin": "http://127.0.0.1:8000",
            },
            data={"document_kind": document_kind.value, "source_label": "etapa_333_test"},
            files={"file": (filename, payload, mime_type)},
        )
        assert resp.status_code == 201, resp.text

    storage = LocalControlledSyntheticStorage(storage_root, enabled=True, max_bytes=20 * 1024 * 1024)
    worker = ProcessingWorker(create_session_factory(worker_engine), storage, settings)
    stats = worker.process_one_cycle(max_jobs=max_jobs)
    return resp.json(), stats


# =============================================================================
# 1. Pure PDF extraction unit tests: fixtures, allowlist, ambiguity, codes
# =============================================================================


def test_deterministic_extraction_across_all_15_official_synthetic_fixtures() -> None:
    pdf_files = sorted(FIXTURES_DIR.glob("*.pdf"))
    assert len(pdf_files) == 15

    for pdf_path in pdf_files:
        raw_bytes = pdf_path.read_bytes()
        sha = hashlib.sha256(raw_bytes).hexdigest()
        res_1 = extract_pdf_document(raw_bytes, source_sha256_hex=sha)
        res_2 = extract_pdf_document(raw_bytes, source_sha256_hex=sha)

        # Deterministic output across repeated executions
        assert res_1.to_derived_artifact_json_bytes() == res_2.to_derived_artifact_json_bytes()
        assert res_1.outcome == "executed"
        assert res_1.readable is True
        assert res_1.abstained is False
        assert res_1.clinical_approval is False
        assert res_1.administrative_only is True
        assert res_1.page_count == 1
        assert res_1.pages[0].word_count > 10
        assert res_1.pages[0].line_count >= 10
        assert res_1.pages[0].block_count >= 1

        by_key = {f.field_key: f for f in res_1.fields}
        for core_key in ("document_type", "patient", "birth_date", "issue_date", "origin"):
            assert core_key in by_key, f"{pdf_path.name} missing {core_key}"
            assert by_key[core_key].status == ExtractedFieldStatus.EXTRACTED
            assert by_key[core_key].abstained is False
            assert len(by_key[core_key].evidences) == 1
            ev = by_key[core_key].evidences[0]
            assert ev.page_number == 1
            assert 0.0 <= ev.bbox.x <= 1.0 and 0.0 <= ev.bbox.y <= 1.0
            assert 0.0 < ev.bbox.w <= 1.0 and 0.0 < ev.bbox.h <= 1.0
            assert ev.bbox.x + ev.bbox.w <= 1.00001 and ev.bbox.y + ev.bbox.h <= 1.00001

        # Non-allowlisted prefix ('conteudo') must NOT be promoted into extracted fields
        assert "conteudo" in res_1.unrecognized_prefixed_labels
        assert "conteudo" not in by_key

        if pdf_path.name == "sem-identificador.pdf":
            assert "identifier" not in by_key
            assert "identifier" in res_1.absent_field_keys
        elif pdf_path.name == "identidade-divergente.pdf":
            assert by_key["identifier"].normalized_value == "SYN-P02"
            assert by_key["birth_date"].normalized_value == "1990-09-03"
        elif pdf_path.name.endswith("-completa.pdf") or pdf_path.name.endswith("-completo.pdf"):
            assert by_key["procedure"].normalized_value == "Facoemulsificacao com implante de LIO"
            assert by_key["procedure_code_system"].normalized_value == "SIGTAP-FICTICIO"
            assert by_key["procedure_code"].normalized_value == "04.05.05.011-9"
            assert by_key["laterality"].raw_value == "Olho Direito (OD)"
            assert by_key["laterality"].normalized_value == "OD"


def test_explicit_allowlist_normalization_ambiguity_and_code_without_system() -> None:
    pdf_complex = _build_synthetic_pdf(
        [
            {
                "lines": [
                    (40, 780, "Paciente:   Pessoa   Acentuada  Érika  "),
                    (40, 760, "Data de nascimento: 29/02/2024"),
                    (40, 740, "Emissão: 31/02/2026"),
                    (40, 720, "Identificador: SYN-101"),
                    (40, 700, "Identificador: SYN-202"),
                    (40, 680, "Origem: Instituição Teste"),
                    (40, 660, "Origem: Instituição Teste"),
                    (40, 640, "Subfamília:"),
                    (40, 620, "Tipo: Avaliação"),
                    (40, 600, "Codigo: 04.05.05.011-9"),
                    (40, 580, "Lateralidade: Esquerda ou direita"),
                    (40, 560, "Observacao clinica: texto fora da allowlist nao deve virar campo"),
                ]
            },
            {
                "lines": [
                    (40, 760, "Origem: Instituição Teste"),
                    (40, 740, "Paciente:   Pessoa   Acentuada  Érika  "),
                ]
            },
        ]
    )
    res = extract_pdf_document(pdf_complex)
    by_key = {f.field_key: f for f in res.fields}

    # Accented + extra whitespace raw preserved vs conservative NFC normalization
    assert by_key["patient"].status == ExtractedFieldStatus.EXTRACTED
    assert by_key["patient"].raw_value == "  Pessoa   Acentuada  Érika  "
    assert by_key["patient"].normalized_value == "Pessoa Acentuada Érika"
    # Repeated identical values on pages 1 & 2 keep ALL spatial evidences
    assert len(by_key["patient"].evidences) == 2
    assert [e.page_number for e in by_key["patient"].evidences] == [1, 2]
    assert len(by_key["origin"].evidences) == 3

    # Valid leap year date -> ISO; invalid calendar date 31/02/2026 -> abstained with raw preserved
    assert by_key["birth_date"].status == ExtractedFieldStatus.EXTRACTED
    assert by_key["birth_date"].normalized_value == "2024-02-29"
    assert by_key["issue_date"].status == ExtractedFieldStatus.ABSTAINED
    assert by_key["issue_date"].abstained is True
    assert by_key["issue_date"].raw_value == "31/02/2026"
    assert by_key["issue_date"].normalized_value is None
    assert by_key["issue_date"].metadata_json["reason_code"] == "MALFORMED_DATE"

    # Incompatible multiple values -> AMBIGUOUS with ALL candidate evidences kept
    assert by_key["identifier"].status == ExtractedFieldStatus.AMBIGUOUS
    assert by_key["identifier"].abstained is True
    assert by_key["identifier"].normalized_value is None
    assert by_key["identifier"].metadata_json["reason_code"] == "MULTIPLE_INCOMPATIBLE_VALUES"
    assert by_key["identifier"].metadata_json["candidate_raw_values"] == ["SYN-101", "SYN-202"]
    assert len(by_key["identifier"].evidences) == 2

    # Empty prefix -> abstained cleanly with marker box
    assert by_key["subfamily"].status == ExtractedFieldStatus.ABSTAINED
    assert by_key["subfamily"].abstained is True
    assert by_key["subfamily"].metadata_json["reason_code"] == "EMPTY_VALUE"
    assert len(by_key["subfamily"].evidences) == 1

    # Code without identified coding system -> MUST NOT normalize/transform code
    assert by_key["procedure_code"].status == ExtractedFieldStatus.ABSTAINED
    assert by_key["procedure_code"].abstained is True
    assert by_key["procedure_code"].raw_value == "04.05.05.011-9"
    assert by_key["procedure_code"].normalized_value is None
    assert by_key["procedure_code"].metadata_json["reason_code"] == "CODE_SYSTEM_UNIDENTIFIED"
    assert len(by_key["procedure_code"].evidences) == 1

    # Ambiguous / unrecognized laterality -> abstained, never inferred
    assert by_key["laterality"].status == ExtractedFieldStatus.ABSTAINED
    assert by_key["laterality"].abstained is True
    assert by_key["laterality"].normalized_value is None

    # Conservative known doc type & ignored non-allowlisted line
    assert by_key["document_type"].raw_value == "Avaliação"
    assert by_key["document_type"].normalized_value == "avaliacao"
    assert "observacao clinica" not in by_key
    assert "observacao clinica" in res.unrecognized_prefixed_labels


# =============================================================================
# 2. Coordinates: 0/90/180/270 rotations, CropBox != MediaBox & no silent clip
# =============================================================================


@pytest.mark.parametrize(
    ("rotation", "mediabox", "cropbox", "expected_x", "expected_y", "expected_w_gt_h"),
    [
        (0, (0, 0, 595, 842), (0, 0, 595, 842), 100 / 595, 132.48 / 842, True),
        (90, (0, 0, 595, 842), (0, 0, 595, 842), 697.5 / 842, 100 / 595, False),
        (180, (0, 0, 595, 842), (0, 0, 595, 842), 361.0 / 595, 697.5 / 842, True),
        (270, (0, 0, 595, 842), (0, 0, 595, 842), 132.48 / 842, 361.0 / 595, False),
        (0, (-20, -30, 580, 770), (30, 70, 480, 720), 50 / 450, 108 / 650, True),
        (90, (-20, -30, 580, 770), (30, 70, 480, 720), 530 / 650, 50 / 450, False),
        (180, (-20, -30, 580, 770), (30, 70, 480, 720), 266.6 / 450, 530 / 650, True),
        (270, (-20, -30, 580, 770), (30, 70, 480, 720), 108 / 650, 266.6 / 450, False),
    ],
)
def test_rotation_and_cropbox_coordinate_transformations_match_visual_viewport(
    rotation: int,
    mediabox: tuple[int, int, int, int],
    cropbox: tuple[int, int, int, int],
    expected_x: float,
    expected_y: float,
    expected_w_gt_h: bool,
) -> None:
    pdf_bytes = _build_synthetic_pdf(
        [
            {
                "mediabox": mediabox,
                "cropbox": cropbox,
                "rotate": rotation,
                "lines": [
                    (
                        100 if mediabox[0] == 0 else 80,
                        700 if mediabox[0] == 0 else 600,
                        "Paciente: Box Geometria",
                    ),
                    (
                        380 if mediabox[0] == 0 else 360,
                        120 if mediabox[0] == 0 else 100,
                        "Lateralidade: OD",
                    ),
                ],
            }
        ]
    )
    res = extract_pdf_document(pdf_bytes)
    assert res.outcome == "executed"
    assert res.pages[0].rotation == rotation
    by_key = {f.field_key: f for f in res.fields}
    bbox = by_key["patient"].evidences[0].bbox
    assert 0.0 <= bbox.x <= 1.0 and 0.0 <= bbox.y <= 1.0
    assert bbox.x + bbox.w <= 1.00001 and bbox.y + bbox.h <= 1.00001
    assert abs(bbox.x - expected_x) < 0.03, f"rot={rotation} got x={bbox.x}, expected~{expected_x}"
    assert abs(bbox.y - expected_y) < 0.03, f"rot={rotation} got y={bbox.y}, expected~{expected_y}"
    assert (bbox.w > bbox.h) is expected_w_gt_h

    # Near-edge text (right/bottom edge within cropbox) remains inside [0, 1]
    lat_bbox = by_key["laterality"].evidences[0].bbox
    assert 0.0 <= lat_bbox.x <= 1.0 and 0.0 <= lat_bbox.y <= 1.0
    assert lat_bbox.x + lat_bbox.w <= 1.00001 and lat_bbox.y + lat_bbox.h <= 1.00001


def test_invalid_bounding_box_is_never_clipped_and_forces_abstention() -> None:
    with pytest.raises(InvalidBoundingBoxError):
        normalize_ltpage_bbox_to_viewport(
            raw_bbox=(-15.0, 700.0, 120.0, 712.0),
            crop_lt_bbox=(0.0, 0.0, 595.0, 842.0),
        )
    with pytest.raises(InvalidBoundingBoxError):
        normalize_ltpage_bbox_to_viewport(
            raw_bbox=(550.0, 700.0, 620.0, 712.0),
            crop_lt_bbox=(0.0, 0.0, 595.0, 842.0),
        )

    # Text placed outside CropBox (x < cropbox_left) triggers INVALID_BOUNDING_BOX without clipping
    out_of_crop_pdf = _build_synthetic_pdf(
        [
            {
                "mediabox": (0, 0, 595, 842),
                "cropbox": (100, 100, 500, 750),
                "lines": [(10, 700, "Paciente: Fora Do CropBox")],
            }
        ]
    )
    res = extract_pdf_document(out_of_crop_pdf)
    assert res.outcome == "abstained"
    assert res.pages[0].status == "abstained"
    assert res.pages[0].reason_code == "INVALID_BOUNDING_BOX"
    assert res.pages[0].invalid_bbox_count >= 1
    assert res.fields == []


# =============================================================================
# 3. Abstention & parser resource limits: scanned, partial, PNG, encrypted, corrupt
# =============================================================================


def test_abstention_for_scanned_partial_empty_garbage_encrypted_corrupt_and_limits() -> None:
    scanned_pdf = _build_synthetic_pdf([{"image_only": True}])
    res_scan = extract_pdf_document(scanned_pdf)
    assert res_scan.outcome == "abstained"
    assert res_scan.readable is False
    assert res_scan.ocr_available is False
    assert res_scan.pages[0].has_image_objects is True
    assert res_scan.fields == []

    empty_pdf = _build_synthetic_pdf([{"lines": []}])
    res_empty = extract_pdf_document(empty_pdf)
    assert res_empty.outcome == "abstained"
    assert res_empty.reason_code == "EMPTY_PAGE"
    assert res_empty.fields == []

    partial_pdf = _build_synthetic_pdf(
        [
            {"lines": [(50, 750, "Paciente: Pessoa Parcial"), (50, 730, "Lateralidade: OE")]},
            {"image_only": True},
        ]
    )
    res_partial = extract_pdf_document(partial_pdf)
    assert res_partial.outcome == "partial"
    assert res_partial.partial is True
    assert res_partial.abstained is True
    assert res_partial.abstained_pages == [2]
    assert {f.field_key: f.normalized_value for f in res_partial.fields} == {
        "patient": "Pessoa Parcial",
        "laterality": "OE",
    }

    garbage_pdf = _build_synthetic_pdf(
        [{"raw_stream": "BT /F1 12 Tf 40 700 Td <01020304> Tj ET"}]
    )
    res_garbage = extract_pdf_document(garbage_pdf)
    assert res_garbage.outcome == "abstained"
    assert res_garbage.pages[0].reason_code == "INVALID_TEXT_LAYER"
    assert res_garbage.fields == []

    encrypted_pdf = _build_synthetic_pdf(
        [{"lines": [(40, 700, "Paciente: Encrypted Secret")]}], encrypted=True
    )
    with pytest.raises(PdfExtractionError) as enc_err:
        extract_pdf_document(encrypted_pdf)
    assert enc_err.value.error_code == "PDF_ENCRYPTED"

    # Structurally wrapped broken body (passes %PDF- / %%EOF upload probe, fails parser)
    corrupt_pdf = b"%PDF-1.4\n% broken xref and catalog\nnot-a-valid-xref-stream\n%%EOF\n"
    with pytest.raises(PdfExtractionError) as corr_err:
        extract_pdf_document(corrupt_pdf)
    assert corr_err.value.error_code == "PDF_CORRUPTED"

    multi_page_pdf = _build_synthetic_pdf(
        [{"lines": [(40, 700, "Paciente: Page 1")]}, {"lines": [(40, 700, "Origem: Page 2")]}, {"lines": [(40, 700, "Tipo: laudo")]}]
    )
    with pytest.raises(PdfExtractionError) as pg_lim:
        extract_pdf_document(multi_page_pdf, limits=PdfExtractionLimits(max_pages=2))
    assert pg_lim.value.error_code == "PDF_PAGE_LIMIT_EXCEEDED"

    with pytest.raises(PdfExtractionError) as char_lim:
        extract_pdf_document(multi_page_pdf, limits=PdfExtractionLimits(max_extracted_chars=10))
    assert char_lim.value.error_code == "PDF_CHAR_LIMIT_EXCEEDED"

    with pytest.raises(PdfExtractionError) as word_lim:
        extract_pdf_document(multi_page_pdf, limits=PdfExtractionLimits(max_words=2))
    assert word_lim.value.error_code == "PDF_WORD_LIMIT_EXCEEDED"

    with pytest.raises(PdfExtractionError) as timeout_lim:
        extract_pdf_document(multi_page_pdf, limits=PdfExtractionLimits(timeout_seconds=-1.0))
    assert timeout_lim.value.error_code == "PDF_EXTRACTION_TIMEOUT"


# =============================================================================
# 4. End-to-end Worker Chaining, Derived Artifact Security, HTTP API & RBAC
# =============================================================================


def test_end_to_end_pipeline_fixture_extraction_api_and_privacy_guarantees(
    migrated_engine, app_engine, worker_engine, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]
    fixture_bytes = (FIXTURES_DIR / "laudo-completo.pdf").read_bytes()
    fixture_sha = hashlib.sha256(fixture_bytes).hexdigest()

    caplog.set_level(logging.INFO, logger=APP_LOGGER_NAME)
    up_body, stats = _upload_and_process(
        app,
        worker_engine,
        env["settings"],
        env["storage_root"],
        org_id=org_a_id,
        case_id=case_a_id,
        actor=env["actors"]["operator"],
        filename="laudo-completo.pdf",
        payload=fixture_bytes,
        mime_type="application/pdf",
    )
    assert stats.claimed == 2
    assert stats.succeeded == 2
    assert stats.failed == 0

    doc_id = up_body["document_id"]
    ver_id = up_body["current_version"]["version_id"]

    # Private derived text artifact exists on disk with SHA-256 recorded cleanly in result_json,
    # never readable through public storage API or HTTP content routes, and no doc text logged.
    derived_files = list((env["storage_root"] / org_a_id / "derived").glob("*.json"))
    assert len(derived_files) == 1
    derived_sha = hashlib.sha256(derived_files[0].read_bytes()).hexdigest()
    derived_key = f"{org_a_id}/derived/{derived_files[0].name}"

    storage = LocalControlledSyntheticStorage(env["storage_root"], enabled=True)
    with pytest.raises(Exception):
        storage.read_synthetic_bytes(organization_id=org_a_id, storage_key=derived_key)

    log_blob = "\n".join(rec.getMessage() + str(getattr(rec, "__dict__", {})) for rec in caplog.records)
    assert "Pessoa Sintetica Alfa" not in log_blob
    assert "04.05.05.011-9" not in log_blob
    assert "SIGTAP-FICTICIO" not in log_blob

    # Consultation HTTP endpoints require auth, enforce RBAC, and expose full traceability
    with TestClient(app) as anon_client:
        assert (
            anon_client.get(
                f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/extracted-fields"
            ).status_code
            == 401
        )
        assert (
            anon_client.get(
                f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/evidence"
            ).status_code
            == 401
        )

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["readonly"]["session_cookie"])
        runs_payload = client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs",
            params={"document_version_id": ver_id},
        ).json()
        assert runs_payload["total"] == 2
        by_step = {r["step_type"]: r for r in runs_payload["processing_runs"]}
        verify_run = by_step["verify_object_integrity"]
        extract_run = by_step["extract_pdf_text"]
        assert verify_run["status"] == "succeeded"
        assert extract_run["status"] == "succeeded"
        assert extract_run["readable"] is True
        assert extract_run["readiness_state"] is None
        assert extract_run["result_json"]["outcome"] == "executed"
        assert extract_run["result_json"]["derived_artifact_sha256"] == derived_sha
        assert extract_run["result_json"]["clinical_approval"] is False
        assert extract_run["result_json"]["administrative_only"] is True
        assert "Pessoa Sintetica Alfa" not in json.dumps(extract_run["result_json"])

        ef_resp = client.get(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/extracted-fields"
        )
        assert ef_resp.status_code == 200
        assert ef_resp.headers["cache-control"].startswith("no-store")
        ef_body = ef_resp.json()
        assert ef_body["source_sha256_hex"] == fixture_sha
        assert ef_body["latest_processing_run_id"] == extract_run["processing_run_id"]
        assert ef_body["latest_outcome"] == "executed"
        assert ef_body["clinical_approval"] is False
        assert ef_body["administrative_only"] is True

        fields_by_key = {f["field_key"]: f for f in ef_body["extracted_fields"]}
        assert fields_by_key["patient"]["raw_value"] == "Pessoa Sintetica Alfa"
        assert fields_by_key["patient"]["normalized_value"] == "Pessoa Sintetica Alfa"
        assert fields_by_key["birth_date"]["raw_value"] == "12/04/1986"
        assert fields_by_key["birth_date"]["normalized_value"] == "1986-04-12"
        assert fields_by_key["laterality"]["raw_value"] == "Olho Direito (OD)"
        assert fields_by_key["laterality"]["normalized_value"] == "OD"
        assert fields_by_key["procedure_code"]["normalized_value"] == "04.05.05.011-9"
        assert len(fields_by_key["patient"]["evidences"]) == 1

        ev_resp = client.get(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/evidence",
            params={"page_number": 1, "field_key": "laterality"},
        )
        assert ev_resp.status_code == 200
        ev_body = ev_resp.json()
        assert ev_body["total"] == 1
        ev_item = ev_body["evidence_references"][0]
        assert ev_item["field_key"] == "laterality"
        assert ev_item["page_number"] == 1
        assert ev_item["quote_excerpt"] == "Lateralidade: Olho Direito (OD)"
        assert ev_item["extractor_version"] == env["settings"].worker_extract_pdf_text_extractor_version

        for raw_txt in (ef_resp.text, ev_resp.text):
            assert env["storage_root"].as_posix() not in raw_txt
            assert "storage_key" not in raw_txt
            assert "lease_token" not in raw_txt
            assert "postgresql" not in raw_txt

        # Cross-tenant isolation via Org B session
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["org_b_admin"]["session_cookie"])
        assert (
            client.get(
                f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/extracted-fields"
            ).status_code
            == 403
        )
        assert (
            client.get(
                f"/api/v1/organizations/{env['org_b_id']}/documents/{doc_id}/versions/{ver_id}/extracted-fields"
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/organizations/{env['org_b_id']}/documents/{doc_id}/versions/{ver_id}/evidence"
            ).status_code
            == 404
        )


def test_png_and_scanned_encrypted_corrupt_end_to_end_pipeline(
    migrated_engine, app_engine, worker_engine, tmp_path: Path
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]

    # 1. PNG -> OCR_NOT_IMPLEMENTED abstention (succeeded, NOT corrupted, zero fields)
    png_doc, _ = _upload_and_process(
        app,
        worker_engine,
        env["settings"],
        env["storage_root"],
        org_id=org_a_id,
        case_id=case_a_id,
        actor=env["actors"]["admin"],
        filename="img.png",
        payload=_make_minimal_png(),
        mime_type="image/png",
        document_kind=DocumentKind.IMAGEM,
    )
    # 2. Scanned PDF -> NO_SELECTABLE_TEXT_OCR_REQUIRED abstention
    scan_doc, _ = _upload_and_process(
        app,
        worker_engine,
        env["settings"],
        env["storage_root"],
        org_id=org_a_id,
        case_id=case_a_id,
        actor=env["actors"]["admin"],
        filename="scan.pdf",
        payload=_build_synthetic_pdf([{"image_only": True}]),
        mime_type="application/pdf",
    )
    # 3. Encrypted PDF -> permanent failure with abstention outcome
    enc_doc, _ = _upload_and_process(
        app,
        worker_engine,
        env["settings"],
        env["storage_root"],
        org_id=org_a_id,
        case_id=case_a_id,
        actor=env["actors"]["admin"],
        filename="enc.pdf",
        payload=_build_synthetic_pdf([{"lines": [(40, 700, "Paciente: Secret")]}], encrypted=True),
        mime_type="application/pdf",
    )
    # 4. Corrupted PDF body -> permanent failure with abstention outcome
    corr_doc, _ = _upload_and_process(
        app,
        worker_engine,
        env["settings"],
        env["storage_root"],
        org_id=org_a_id,
        case_id=case_a_id,
        actor=env["actors"]["admin"],
        filename="broken.pdf",
        payload=b"%PDF-1.4\n% broken object\n%%EOF\n",
        mime_type="application/pdf",
    )

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["reviewer"]["session_cookie"])

        for up_doc, exp_status, exp_reason in (
            (png_doc, ProcessingStatus.SUCCEEDED.value, "OCR_NOT_IMPLEMENTED"),
            (scan_doc, ProcessingStatus.SUCCEEDED.value, "NO_SELECTABLE_TEXT_OCR_REQUIRED"),
            (enc_doc, ProcessingStatus.FAILED.value, "PDF_ENCRYPTED"),
            (corr_doc, ProcessingStatus.FAILED.value, "PDF_CORRUPTED"),
        ):
            doc_id = up_doc["document_id"]
            ver_id = up_doc["current_version"]["version_id"]
            runs = client.get(
                f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/processing-runs",
                params={"document_version_id": ver_id},
            ).json()["processing_runs"]
            extract_run = next(r for r in runs if r["step_type"] == "extract_pdf_text")
            assert extract_run["status"] == exp_status
            assert extract_run["readable"] is False
            assert extract_run["readiness_state"] is None
            assert extract_run["result_json"]["outcome"] == "abstained"
            assert extract_run["result_json"]["reason_code"] == exp_reason
            assert extract_run["result_json"]["clinical_approval"] is False

            fields = client.get(
                f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver_id}/extracted-fields"
            ).json()
            assert fields["total"] == 0

    owner_db = create_session_factory(migrated_engine)()
    try:
        events = AuditEventRepository.list_events(owner_db, TenantContext(organization_id=org_a_id))
        ev_types = [e.event_type for e in events]
        assert ev_types.count("processing_run.abstained") == 2
        assert ev_types.count("processing_run.failed") == 2
        assert AuditEventRepository.verify_chain_detailed(
            owner_db, TenantContext(organization_id=org_a_id)
        ).valid
    finally:
        owner_db.close()


# =============================================================================
# 5. Chaining order, worker crash recovery, reprocessing, versions & concurrency
# =============================================================================


def test_pipeline_blocks_extract_without_integrity_recovers_crash_and_preserves_reprocess_history(
    migrated_engine, app_engine, worker_engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    org_a_id = env["org_a_id"]
    case_a_id = env["case_a_id"]
    pdf_v1 = _build_synthetic_pdf(
        [{"lines": [(40, 740, "Paciente: Versao Um"), (40, 720, "Origem: Origem A")]}]
    )
    pdf_v2 = _build_synthetic_pdf(
        [{"lines": [(40, 740, "Paciente: Versao Dois"), (40, 720, "Origem: Origem B")]}]
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
            data={"document_kind": DocumentKind.LAUDO.value, "source_label": "chaining_guard"},
            files={"file": ("doc.pdf", pdf_v1, "application/pdf")},
        ).json()
    doc_id = up["document_id"]
    ver1_id = up["current_version"]["version_id"]

    storage = LocalControlledSyntheticStorage(env["storage_root"], enabled=True)
    # 1. Attempting to enqueue/claim extract_pdf_text while verify_object_integrity hasn't succeeded yields nothing
    worker_factory = create_session_factory(worker_engine)
    owner_db = create_session_factory(migrated_engine)()
    try:
        # Directly queue an isolated extract run -> claimer MUST refuse until integrity succeeds
        orphan_extract = ProcessingQueueRepository.enqueue_run(
            owner_db,
            TenantContext(organization_id=org_a_id, actor_user_id=env["actors"]["admin"]["user_id"]),
            document_version_id=ver1_id,
            step_type=ProcessingStepType.EXTRACT_PDF_TEXT.value,
            extractor_version=env["settings"].worker_extract_pdf_text_extractor_version,
            idempotency_key="premature-extract-test",
        )
        owner_db.commit()
        premature_id = orphan_extract.id
    finally:
        owner_db.close()

    ext_only_worker = ProcessingWorker(
        worker_factory,
        storage,
        env["settings"],
        worker_id="ext-only",
        step_types=ProcessingStepType.EXTRACT_PDF_TEXT.value,
    )
    assert ext_only_worker.process_one_cycle(max_jobs=5).claimed == 0

    # Complete verify_object_integrity ONLY (no duplicate extract run created since premature exists)
    ver_only_worker = ProcessingWorker(
        worker_factory,
        storage,
        env["settings"],
        worker_id="ver-only",
        step_types=ProcessingStepType.VERIFY_OBJECT_INTEGRITY.value,
    )
    assert ver_only_worker.process_one_cycle(max_jobs=5).succeeded == 1

    # 2. Simulate failure AFTER extraction & derived artifact write, BEFORE DB commit -> zero partial DB rows & artifact deleted
    orig_complete = ProcessingQueueRepository.complete_extraction_run

    def _boom_complete(*_args, **_kwargs):
        raise LeaseOwnershipError("Simulated crash before committing extraction")

    monkeypatch.setattr(ProcessingQueueRepository, "complete_extraction_run", staticmethod(_boom_complete))
    crash_stats = ext_only_worker.process_one_cycle(max_jobs=2)
    assert crash_stats.lease_lost == 1
    assert list((env["storage_root"] / org_a_id / "derived").glob("*.json")) == []
    monkeypatch.setattr(ProcessingQueueRepository, "complete_extraction_run", staticmethod(orig_complete))

    # Expire lease so recovery worker reclaims premature_id safely without duplicate rows
    owner_exp = create_session_factory(migrated_engine)()
    try:
        apply_pg_rls_context(owner_exp, organization_id=org_a_id)
        owner_exp.execute(
            text("UPDATE processing_runs SET lease_expires_at = :exp WHERE id = :rid"),
            {"exp": utc_now() - timedelta(seconds=30), "rid": premature_id},
        )
        owner_exp.commit()
    finally:
        owner_exp.close()

    rec_stats = ext_only_worker.process_one_cycle(max_jobs=5)
    assert rec_stats.reclaimed_leases == 1
    assert rec_stats.succeeded == 1

    # Verify DB unique constraint blocks duplicate field_key inside the same processing run
    dup_db = create_session_factory(migrated_engine)()
    try:
        apply_pg_rls_context(dup_db, organization_id=org_a_id)
        dup_db.add(
            ExtractedField(
                organization_id=org_a_id,
                processing_run_id=premature_id,
                document_version_id=ver1_id,
                field_key="patient",
                raw_value="Dup",
                normalized_value="Dup",
                status="extracted",
                abstained=False,
            )
        )
        with pytest.raises(IntegrityError):
            dup_db.flush()
        dup_db.rollback()
    finally:
        dup_db.close()

    # 3. Reprocess v1 with a NEW extractor_version -> old extraction preserved, new extraction added
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        re_resp = client.post(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver1_id}/reprocess",
            headers={
                CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
                "Origin": "http://127.0.0.1:8000",
            },
        )
        assert re_resp.status_code == 201

    settings_v2_ext = env["settings"].model_copy(
        update={"worker_extract_pdf_text_extractor_version": "pdfminer-deterministic-3.3.4"}
    )
    v2_worker = ProcessingWorker(worker_factory, storage, settings_v2_ext, worker_id="ext-v2")
    assert v2_worker.process_one_cycle(max_jobs=10).succeeded == 2

    # 4. Also register document version v2 -> version isolation preserved cleanly
    owner_v2 = create_session_factory(migrated_engine)()
    try:
        ver2 = InstitutionalService.store_and_register_document_version(
            owner_v2,
            TenantContext(
                organization_id=org_a_id,
                actor_user_id=env["actors"]["admin"]["user_id"],
                session_token_hash=hmac_token_digest(
                    env["actors"]["admin"]["session_cookie"],
                    secret=env["settings"].session_secret,
                    context="session_token",
                ),
            ),
            storage=storage,
            document_id=doc_id,
            version_number=2,
            mime_type="application/pdf",
            content=pdf_v2,
            original_filename="doc-v2.pdf",
            enqueue_processing=True,
        )
        owner_v2.commit()
        ver2_id = ver2.id
    finally:
        owner_v2.close()

    assert v2_worker.process_one_cycle(max_jobs=10).succeeded == 2

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["reviewer"]["session_cookie"])
        v1_all = client.get(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver1_id}/extracted-fields"
        ).json()
        # Both extractor runs preserved (2 fields x 2 runs = 4 records)
        assert v1_all["total"] == 4
        assert {item["extractor_version"] for item in v1_all["extracted_fields"]} == {
            "pdfminer-deterministic-3.3.3",
            "pdfminer-deterministic-3.3.4",
        }
        v1_latest = client.get(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver1_id}/extracted-fields",
            params={"latest_only": "true"},
        ).json()
        assert v1_latest["total"] == 2
        assert all(
            item["extractor_version"] == "pdfminer-deterministic-3.3.4"
            for item in v1_latest["extracted_fields"]
        )

        v2_fields = client.get(
            f"/api/v1/organizations/{org_a_id}/documents/{doc_id}/versions/{ver2_id}/extracted-fields"
        ).json()
        v2_map = {item["field_key"]: item["normalized_value"] for item in v2_fields["extracted_fields"]}
        assert v2_map == {"patient": "Versao Dois", "origin": "Origem B"}

    # Verify concurrent execution across two workers for multiple PDFs
    conc_docs = [
        _build_synthetic_pdf([{"lines": [(40, 740, f"Paciente: Conc {i}")]}])
        for i in range(4)
    ]
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin"]["csrf_cookie"])
        for idx, c_bytes in enumerate(conc_docs):
            r = client.post(
                f"/api/v1/organizations/{org_a_id}/cases/{case_a_id}/documents",
                headers={
                    CSRF_HEADER_NAME: env["actors"]["admin"]["csrf_cookie"],
                    "Origin": "http://127.0.0.1:8000",
                },
                data={"document_kind": DocumentKind.LAUDO.value, "source_label": f"conc_{idx}"},
                files={"file": (f"c-{idx}.pdf", c_bytes, "application/pdf")},
            )
            assert r.status_code == 201

    w_a = ProcessingWorker(worker_factory, storage, env["settings"], worker_id="conc-ext-1")
    w_b = ProcessingWorker(worker_factory, storage, env["settings"], worker_id="conc-ext-2")
    with ThreadPoolExecutor(max_workers=2) as pool:
        f_a = pool.submit(w_a.process_one_cycle, max_jobs=10)
        f_b = pool.submit(w_b.process_one_cycle, max_jobs=10)
        s_a, s_b = f_a.result(), f_b.result()
    assert s_a.claimed + s_b.claimed == 9
    assert s_a.succeeded + s_b.succeeded == 9


# =============================================================================
# 6. PostgreSQL 16 Real FORCE RLS & jyxia_worker Separation Verification
# =============================================================================


def test_postgresql_rls_and_tenant_isolation_for_extracted_fields_and_evidence(
    migrated_engine, app_engine, worker_engine, tmp_path: Path
) -> None:
    if app_engine.dialect.name != "postgresql":
        # Still run SQLite repository tenant-boundary verification locally
        env = _seed_workspace(migrated_engine, app_engine, tmp_path)
        app = create_app(env["settings"])
        up_a, _ = _upload_and_process(
            app,
            worker_engine,
            env["settings"],
            env["storage_root"],
            org_id=env["org_a_id"],
            case_id=env["case_a_id"],
            actor=env["actors"]["admin"],
            filename="laudo.pdf",
            payload=(FIXTURES_DIR / "laudo.pdf").read_bytes(),
            mime_type="application/pdf",
        )
        owner_db = create_session_factory(migrated_engine)()
        try:
            ver_id = up_a["current_version"]["version_id"]
            items_b, _ = ProcessingQueueRepository.list_document_version_extracted_fields(
                owner_db,
                TenantContext(organization_id=env["org_b_id"]),
                document_version_id=ver_id,
            )
            assert items_b == []
        finally:
            owner_db.close()
        return

    env = _seed_workspace(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    up_a, stats_a = _upload_and_process(
        app,
        worker_engine,
        env["settings"],
        env["storage_root"],
        org_id=env["org_a_id"],
        case_id=env["case_a_id"],
        actor=env["actors"]["admin"],
        filename="pg-laudo.pdf",
        payload=(FIXTURES_DIR / "laudo-completo.pdf").read_bytes(),
        mime_type="application/pdf",
    )
    assert stats_a.succeeded == 2

    app_factory = create_session_factory(app_engine)
    sess_no_ctx = app_factory()
    try:
        clear_pg_rls_context(sess_no_ctx)
        assert sess_no_ctx.execute(text("SELECT count(*) FROM extracted_fields")).scalar() == 0
        assert sess_no_ctx.execute(text("SELECT count(*) FROM evidence_references")).scalar() == 0
    finally:
        sess_no_ctx.close()

    sess_b = app_factory()
    try:
        apply_pg_rls_context(
            sess_b, organization_id=env["org_b_id"], user_id=env["actors"]["org_b_admin"]["user_id"]
        )
        assert (
            sess_b.execute(
                select(ExtractedField).where(ExtractedField.organization_id == env["org_a_id"])
            ).all()
            == []
        )
        assert (
            sess_b.execute(
                select(EvidenceReference).where(EvidenceReference.organization_id == env["org_a_id"])
            ).all()
            == []
        )
        # Attempted cross-tenant update under FORCE RLS affects 0 rows
        upd_count = sess_b.execute(
            text("UPDATE extracted_fields SET normalized_value = 'tampered' WHERE organization_id = :oa"),
            {"oa": env["org_a_id"]},
        ).rowcount
        assert upd_count == 0
        sess_b.rollback()
    finally:
        sess_b.close()

    sess_a = app_factory()
    try:
        apply_pg_rls_context(
            sess_a, organization_id=env["org_a_id"], user_id=env["actors"]["admin"]["user_id"]
        )
        cnt_a = sess_a.execute(text("SELECT count(*) FROM extracted_fields")).scalar()
        assert cnt_a == 11
    finally:
        sess_a.close()
