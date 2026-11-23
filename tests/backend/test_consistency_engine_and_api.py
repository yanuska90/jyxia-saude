"""Comprehensive deterministic consistency engine, worker pipeline, RBAC/RLS API, and benchmark tests (Etapa 3.3.4)."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient
import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.core.config import Settings
from app.core.constants import (
    AxisName,
    AxisStatus,
    CaseReadinessState,
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    DocumentKind,
    ExtractedFieldStatus,
    HumanReviewAction,
    IDEMPOTENCY_KEY_HEADER_NAME,
    OrganizationRole,
    ProcessingStatus,
    SESSION_COOKIE_NAME,
)
from app.core.session_crypto import generate_opaque_token, hmac_token_digest
from app.db.session import apply_pg_rls_context, clear_pg_rls_context, create_session_factory
from app.main import create_app
from app.models.entities import (
    ConsistencyAssessment,
    ConsistencyAxisEvidence,
)
from app.repositories.identity import IdentityAndSessionRepository
from app.repositories.institutional import (
    AuditEventRepository,
    CaseAndDocumentRepository,
    LeaseOwnershipError,
    OrganizationRepository,
    ProcessingQueueRepository,
)
from app.schemas.tenant import HumanReviewCreateInput, TenantContext
from app.services.institutional_service import InstitutionalService
from app.services.consistency_engine import (
    CaseConsistencyInput,
    CaseDocumentInput,
    DocumentVersionInput,
    EvidenceInput,
    ExtractedFieldInput,
    HumanReviewInput,
    evaluate_case_consistency,
)
from app.services.processing_worker import ProcessingWorker
from app.services.storage import LocalControlledSyntheticStorage

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_DIR = REPO_ROOT / "frontend" / "public" / "fixtures"

_BASE_TS = datetime(2026, 11, 15, 10, 0, tzinfo=timezone.utc)


def _ev(
    ev_id: str,
    *,
    org_id: str = "org-1",
    ver_id: str,
    field_id: str,
    page: int = 1,
    bbox: tuple[float, float, float, float] = (0.1, 0.2, 0.4, 0.03),
    quote: str = "excerpt",
) -> EvidenceInput:
    return EvidenceInput(
        evidence_id=ev_id,
        organization_id=org_id,
        document_version_id=ver_id,
        extracted_field_id=field_id,
        page_number=page,
        bbox=bbox,
        quote_excerpt=quote,
        extraction_method="pdf_text_geometry_pdfminer",
    )


def _field(
    field_id: str,
    key: str,
    raw: str | None,
    norm: str | None = None,
    *,
    org_id: str = "org-1",
    ver_id: str,
    run_id: str = "run-ext-1",
    status: str = ExtractedFieldStatus.EXTRACTED.value,
    abstained: bool = False,
    metadata: dict[str, Any] | None = None,
    page: int = 1,
    bbox: tuple[float, float, float, float] = (0.1, 0.2, 0.4, 0.03),
    with_evidence: bool = True,
) -> ExtractedFieldInput:
    evs: tuple[EvidenceInput, ...] = (
        (
            _ev(
                f"ev-{field_id}",
                org_id=org_id,
                ver_id=ver_id,
                field_id=field_id,
                page=page,
                bbox=bbox,
                quote=f"{key}: {raw}",
            ),
        )
        if with_evidence
        else ()
    )
    return ExtractedFieldInput(
        extracted_field_id=field_id,
        organization_id=org_id,
        document_version_id=ver_id,
        processing_run_id=run_id,
        field_key=key,
        raw_value=raw,
        normalized_value=norm if norm is not None else raw,
        status=status,
        abstained=abstained,
        metadata_json=metadata or {},
        evidences=evs,
    )


def _make_doc(
    doc_id: str,
    kind: str = DocumentKind.LAUDO.value,
    *,
    fields: list[ExtractedFieldInput],
    ver_id: str | None = None,
    version_number: int = 1,
    sha256_hex: str | None = None,
    created_at: datetime = _BASE_TS,
    is_current: bool = True,
    superseded_by: str | None = None,
    extraction_status: str = ProcessingStatus.SUCCEEDED.value,
    extraction_readable: bool = True,
    extraction_outcome: str = "extracted",
    extractor_version: str = "pdfminer-deterministic-3.3.3",
    reviewed: bool = False,
    quarantined: bool = False,
    discarded_at: datetime | None = None,
    extra_versions: tuple[DocumentVersionInput, ...] = (),
) -> CaseDocumentInput:
    v_id = ver_id or f"ver-{doc_id}-{version_number}"
    reviews = (
        (
            HumanReviewInput(
                review_id=f"rev-{v_id}",
                document_version_id=v_id,
                action_type=HumanReviewAction.OBSERVED.value,
                field_key=None,
                policy_version="3.3.4",
                created_at=created_at + timedelta(minutes=5),
            ),
        )
        if reviewed
        else ()
    )
    current_v = DocumentVersionInput(
        version_id=v_id,
        document_id=doc_id,
        version_number=version_number,
        sha256_hex=sha256_hex or (doc_id[-1] if doc_id[-1].isalnum() else "a").lower() * 64,
        mime_type="application/pdf",
        created_at=created_at,
        is_current=is_current,
        superseded_by_version_id=superseded_by,
        integrity_status=ProcessingStatus.SUCCEEDED.value,
        extraction_run_id=f"run-ext-{v_id}",
        extraction_status=extraction_status,
        extractor_version=extractor_version,
        extraction_readable=extraction_readable,
        extraction_outcome=extraction_outcome,
        extracted_fields=tuple(fields),
        human_reviews=reviews,
    )
    return CaseDocumentInput(
        document_id=doc_id,
        document_kind=kind,
        document_subfamily=None,
        source_label=f"src-{doc_id}",
        quarantined=quarantined,
        discarded_at=discarded_at,
        versions=extra_versions + (current_v,),
    )


def _complete_fields(
    ver_id: str,
    *,
    patient: str | None = "Pessoa Sintetica Alfa",
    birth_date: str | None = "1986-04-12",
    identifier: str | None = "SYN-P01",
    procedure: str | None = "Facoemulsificacao com implante de LIO",
    code_system: str | None = "SIGTAP-FICTICIO",
    code: str | None = "04.05.05.011-9",
    laterality: str | None = "OD",
    issue_date: str | None = "2026-11-11",
) -> list[ExtractedFieldInput]:
    out: list[ExtractedFieldInput] = []
    if patient is not None:
        out.append(_field(f"p-{ver_id}", "patient", patient, patient, ver_id=ver_id))
    if birth_date is not None:
        out.append(_field(f"b-{ver_id}", "birth_date", birth_date, birth_date, ver_id=ver_id))
    if identifier is not None:
        out.append(_field(f"id-{ver_id}", "identifier", identifier, identifier, ver_id=ver_id))
    if procedure is not None:
        out.append(_field(f"pr-{ver_id}", "procedure", procedure, procedure, ver_id=ver_id))
    if code_system is not None:
        out.append(
            _field(
                f"sys-{ver_id}",
                "procedure_code_system",
                code_system,
                code_system,
                ver_id=ver_id,
            )
        )
    if code is not None:
        out.append(
            _field(
                f"cd-{ver_id}",
                "procedure_code",
                code,
                code,
                ver_id=ver_id,
                metadata={"system_identified": code_system is not None, "code_system": code_system},
            )
        )
    if laterality is not None:
        out.append(_field(f"lat-{ver_id}", "laterality", laterality, laterality, ver_id=ver_id))
    if issue_date is not None:
        out.append(_field(f"iss-{ver_id}", "issue_date", issue_date, issue_date, ver_id=ver_id))
    return out


# =============================================================================
# 1. Domain Engine Matrix: Identity, Procedure, Laterality, Temporality, Global
# =============================================================================


def test_identity_axis_exhaustive_deterministic_rules() -> None:
    d1 = _make_doc("doc-1", DocumentKind.PEDIDO.value, fields=_complete_fields("ver-doc-1-1"))
    d2 = _make_doc("doc-2", DocumentKind.LAUDO.value, fields=_complete_fields("ver-doc-2-1"))
    res_ok = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1, d2))
    )
    assert res_ok.axes[AxisName.IDENTIDADE].status == AxisStatus.OK
    assert res_ok.axes[AxisName.IDENTIDADE].rule_code == "IDENTITY_EXACT_MATCH"
    assert res_ok.readiness_state == CaseReadinessState.PENDENTE  # Human review absent!
    assert res_ok.automated_axes_outcome == "all_ok"

    # Same patient + birth_date, DISTINCT typed identifiers -> CONFLITO (never equated by name!)
    d_diff_id = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", identifier="SYN-P02"),
    )
    res_id_conf = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1, d_diff_id))
    )
    ax_id = res_id_conf.axes[AxisName.IDENTIDADE]
    assert ax_id.status == AxisStatus.CONFLITO
    assert ax_id.rule_code == "IDENTITY_IDENTIFIER_CONFLICT"
    assert len(ax_id.evidence_reference_ids) >= 2
    assert res_id_conf.readiness_state == CaseReadinessState.BLOQUEADO

    # Distinct identifiers + distinct names -> CONFLITO citing both docs
    d_beta = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields(
            "ver-doc-2-1", patient="Pessoa Sintetica Beta", birth_date="1990-09-03", identifier="SYN-P02"
        ),
    )
    res_beta = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1, d_beta))
    )
    assert res_beta.axes[AxisName.IDENTIDADE].status == AxisStatus.CONFLITO
    assert len(res_beta.axes[AxisName.IDENTIDADE].compared_document_ids) == 2

    # Missing identifier -> PENDENTE (never concludes equality by name alone)
    d_no_id = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", identifier=None),
    )
    res_missing = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1, d_no_id))
    )
    assert res_missing.axes[AxisName.IDENTIDADE].status == AxisStatus.PENDENTE

    # Ambiguous intra-document values -> CONFLITO
    f_ambig = _complete_fields("ver-doc-2-1")
    f_ambig = [
        x
        if x.field_key != "identifier"
        else _field(
            "id-ambig",
            "identifier",
            "SYN-P01 | SYN-P02",
            None,
            ver_id="ver-doc-2-1",
            status=ExtractedFieldStatus.AMBIGUOUS.value,
            abstained=True,
        )
        for x in f_ambig
    ]
    res_ambig = evaluate_case_consistency(
        CaseConsistencyInput(
            organization_id="org-1",
            case_id="c1",
            case_code="C1",
            documents=(d1, _make_doc("doc-2", DocumentKind.LAUDO.value, fields=f_ambig)),
        )
    )
    assert res_ambig.axes[AxisName.IDENTIDADE].status == AxisStatus.CONFLITO
    assert res_ambig.axes[AxisName.IDENTIDADE].rule_code == "IDENTITY_AMBIGUOUS_INTRA_DOCUMENT"

    # Insufficient/untyped identifier ("12345" without contract prefix/type) -> ABSTENCAO
    d_untyped = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", identifier="12345"),
    )
    res_untyped = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1, d_untyped))
    )
    assert res_untyped.axes[AxisName.IDENTIDADE].status == AxisStatus.ABSTENCAO
    assert res_untyped.axes[AxisName.IDENTIDADE].rule_code == "IDENTITY_UNTYPED_OR_INVALID_FIELD"

    # Different explicit identifier types (CNS vs SYN) -> ABSTENCAO
    d_cns = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", identifier="CNS: 898001160660761"),
    )
    res_het_id = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1, d_cns))
    )
    assert res_het_id.axes[AxisName.IDENTIDADE].status == AxisStatus.ABSTENCAO
    assert res_het_id.axes[AxisName.IDENTIDADE].rule_code == "IDENTITY_HETEROGENEOUS_IDENTIFIER_TYPES"


def test_procedure_axis_exhaustive_deterministic_rules() -> None:
    # Exact description without codes -> OK with limitation
    d1_tc = _make_doc(
        "doc-1",
        DocumentKind.PEDIDO.value,
        fields=_complete_fields("ver-doc-1-1", code=None, code_system=None),
    )
    d2_tc = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", code=None, code_system=None),
    )
    res_text = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1_tc, d2_tc))
    )
    assert res_text.axes[AxisName.PROCEDIMENTO_CODIGO].status == AxisStatus.OK
    assert "CODE_NOT_PRESENT_IN_ALL_DOCUMENTS_TEXTUAL_ONLY" in res_text.axes[AxisName.PROCEDIMENTO_CODIGO].limitations

    # Same code + same system -> OK
    d1_sys = _make_doc("doc-1", DocumentKind.PEDIDO.value, fields=_complete_fields("ver-doc-1-1"))
    d2_sys = _make_doc("doc-2", DocumentKind.LAUDO.value, fields=_complete_fields("ver-doc-2-1"))
    res_same = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1_sys, d2_sys))
    )
    assert res_same.axes[AxisName.PROCEDIMENTO_CODIGO].status == AxisStatus.OK

    # SAME code across DIFFERENT coding systems -> ABSTENCAO (never treated as equivalent!)
    d2_tuss_same_code = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", code_system="TUSS-FICTICIO", code="04.05.05.011-9"),
    )
    res_diff_sys = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1_sys, d2_tuss_same_code))
    )
    assert res_diff_sys.axes[AxisName.PROCEDIMENTO_CODIGO].status == AxisStatus.ABSTENCAO
    assert res_diff_sys.axes[AxisName.PROCEDIMENTO_CODIGO].rule_code == "PROCEDURE_CODE_EQUAL_DIFFERENT_SYSTEMS"

    # Code WITHOUT coding system -> ABSTENCAO
    f_no_sys = _complete_fields("ver-doc-2-1", code_system=None, code="04.05.05.011-9")
    f_no_sys = [
        x
        if x.field_key != "procedure_code"
        else _field(
            "cd-nosys",
            "procedure_code",
            "04.05.05.011-9",
            None,
            ver_id="ver-doc-2-1",
            status=ExtractedFieldStatus.ABSTAINED.value,
            abstained=True,
            metadata={"reason_code": "MISSING_CODE_SYSTEM", "system_identified": False},
        )
        for x in f_no_sys
    ]
    res_no_sys = evaluate_case_consistency(
        CaseConsistencyInput(
            organization_id="org-1",
            case_id="c1",
            case_code="C1",
            documents=(d1_sys, _make_doc("doc-2", DocumentKind.LAUDO.value, fields=f_no_sys)),
        )
    )
    assert res_no_sys.axes[AxisName.PROCEDIMENTO_CODIGO].status == AxisStatus.ABSTENCAO
    assert res_no_sys.axes[AxisName.PROCEDIMENTO_CODIGO].rule_code == "PROCEDURE_CODE_WITHOUT_SYSTEM"

    # Incompatible descriptions -> CONFLITO (never fuzzy clinical match)
    d2_diff_desc = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", procedure="Vitrectomia posterior via pars plana"),
    )
    res_desc_conf = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1_sys, d2_diff_desc))
    )
    assert res_desc_conf.axes[AxisName.PROCEDIMENTO_CODIGO].status == AxisStatus.CONFLITO
    assert res_desc_conf.axes[AxisName.PROCEDIMENTO_CODIGO].rule_code == "PROCEDURE_DESCRIPTION_CONFLICT"

    # Missing procedure in doc -> PENDENTE
    d2_missing_proc = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", procedure=None, code=None, code_system=None),
    )
    res_proc_pend = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1_sys, d2_missing_proc))
    )
    assert res_proc_pend.axes[AxisName.PROCEDIMENTO_CODIGO].status == AxisStatus.PENDENTE

    # Multiple incompatible occurrences inside one document -> CONFLITO
    f_multi = [
        x
        if x.field_key != "procedure"
        else _field(
            "pr-multi",
            "procedure",
            "Proc A | Proc B",
            None,
            ver_id="ver-doc-2-1",
            status=ExtractedFieldStatus.AMBIGUOUS.value,
            abstained=True,
        )
        for x in _complete_fields("ver-doc-2-1")
    ]
    res_multi = evaluate_case_consistency(
        CaseConsistencyInput(
            organization_id="org-1",
            case_id="c1",
            case_code="C1",
            documents=(d1_sys, _make_doc("doc-2", DocumentKind.LAUDO.value, fields=f_multi)),
        )
    )
    assert res_multi.axes[AxisName.PROCEDIMENTO_CODIGO].status == AxisStatus.CONFLITO


def test_laterality_axis_and_global_states_exhaustive() -> None:
    # OD/OD -> OK; OE/OE -> OK
    for code in ("OD", "OE"):
        d1 = _make_doc("doc-1", DocumentKind.PEDIDO.value, fields=_complete_fields("ver-doc-1-1", laterality=code), reviewed=True)
        d2 = _make_doc("doc-2", DocumentKind.TERMO.value, fields=_complete_fields("ver-doc-2-1", laterality=code), reviewed=True)
        res = evaluate_case_consistency(
            CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1, d2))
        )
        assert res.axes[AxisName.LATERALIDADE].status == AxisStatus.OK
        assert res.readiness_state == CaseReadinessState.CONFERIDA
        assert res.clinical_approval is False
        assert res.administrative_only is True

    # OD/OE -> CONFLITO; Bilateral/OD -> CONFLITO
    d_od = _make_doc("doc-1", DocumentKind.PEDIDO.value, fields=_complete_fields("ver-doc-1-1", laterality="OD"), reviewed=True)
    d_oe = _make_doc("doc-2", DocumentKind.TERMO.value, fields=_complete_fields("ver-doc-2-1", laterality="OE"), reviewed=True)
    d_ao = _make_doc("doc-2", DocumentKind.TERMO.value, fields=_complete_fields("ver-doc-2-1", laterality="AO"), reviewed=True)
    res_od_oe = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d_od, d_oe))
    )
    assert res_od_oe.axes[AxisName.LATERALIDADE].status == AxisStatus.CONFLITO
    assert res_od_oe.axes[AxisName.LATERALIDADE].rule_code == "EXPLICIT_LATERALITY_MISMATCH"
    assert res_od_oe.readiness_state == CaseReadinessState.BLOQUEADO

    res_ao_od = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d_od, d_ao))
    )
    assert res_ao_od.axes[AxisName.LATERALIDADE].status == AxisStatus.CONFLITO
    assert res_ao_od.axes[AxisName.LATERALIDADE].rule_code == "BILATERAL_VS_UNILATERAL_CONFLICT"

    # Explicit NA across docs + reviewed -> NAO_APLICAVEL -> CONFERIDA_COM_ESCOPO_LIMITADO
    d_na1 = _make_doc("doc-1", DocumentKind.PEDIDO.value, fields=_complete_fields("ver-doc-1-1", laterality="NA"), reviewed=True)
    d_na2 = _make_doc("doc-2", DocumentKind.TERMO.value, fields=_complete_fields("ver-doc-2-1", laterality="Nao aplicavel"), reviewed=True)
    res_na = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d_na1, d_na2))
    )
    assert res_na.axes[AxisName.LATERALIDADE].status == AxisStatus.NAO_APLICAVEL
    assert res_na.readiness_state == CaseReadinessState.CONFERIDA_COM_ESCOPO_LIMITADO
    assert res_na.automated_axes_outcome == "limited_scope"

    # Unknown value -> ABSTENCAO (never NA!)
    f_unk = [
        x
        if x.field_key != "laterality"
        else _field(
            "lat-unk",
            "laterality",
            "Central indefinido",
            None,
            ver_id="ver-doc-2-1",
            status=ExtractedFieldStatus.ABSTAINED.value,
            abstained=True,
        )
        for x in _complete_fields("ver-doc-2-1")
    ]
    res_unk = evaluate_case_consistency(
        CaseConsistencyInput(
            organization_id="org-1",
            case_id="c1",
            case_code="C1",
            documents=(d_od, _make_doc("doc-2", DocumentKind.TERMO.value, fields=f_unk, reviewed=True)),
        )
    )
    assert res_unk.axes[AxisName.LATERALIDADE].status == AxisStatus.ABSTENCAO
    assert res_unk.readiness_state == CaseReadinessState.ABSTENCAO

    # Missing field -> PENDENTE (never NA!)
    d_nolat = _make_doc("doc-2", DocumentKind.TERMO.value, fields=_complete_fields("ver-doc-2-1", laterality=None), reviewed=True)
    res_nolat = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d_od, d_nolat))
    )
    assert res_nolat.axes[AxisName.LATERALIDADE].status == AxisStatus.PENDENTE
    assert res_nolat.readiness_state == CaseReadinessState.PENDENTE

    # Out-of-scope evaluated_axes -> omitted axis stays NAO_AVALIADO and global stays ABSTENCAO
    d_ok2 = _make_doc("doc-2", DocumentKind.TERMO.value, fields=_complete_fields("ver-doc-2-1", laterality="OD"), reviewed=True)
    res_uneval = evaluate_case_consistency(
        CaseConsistencyInput(
            organization_id="org-1",
            case_id="c1",
            case_code="C1",
            evaluated_axes=(AxisName.IDENTIDADE, AxisName.PROCEDIMENTO_CODIGO, AxisName.LATERALIDADE),
            documents=(d_od, d_ok2),
        )
    )
    assert res_uneval.axes[AxisName.TEMPORALIDADE].status == AxisStatus.NAO_AVALIADO
    assert res_uneval.readiness_state == CaseReadinessState.ABSTENCAO


def test_temporality_axis_and_evidence_rejection_rules() -> None:
    d1 = _make_doc("doc-1", DocumentKind.PEDIDO.value, fields=_complete_fields("ver-doc-1-1", issue_date="2026-11-11"))
    # Different dates within 30d + later upload with earlier issue_date -> sorted by issue_date cleanly!
    d2_out_of_order = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", issue_date="2026-11-05"),
        created_at=_BASE_TS + timedelta(hours=2),
    )
    res_order = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d2_out_of_order, d1))
    )
    ax_t = res_order.axes[AxisName.TEMPORALIDADE]
    assert ax_t.status == AxisStatus.OK
    assert ax_t.rule_code == "TEMPORALITY_DATES_WITHIN_WINDOW"
    assert "UPLOAD_ORDER_DIFFERS_FROM_ISSUE_ORDER" in ax_t.limitations
    compared_iss = [c for c in ax_t.comparison_items if c["role_in_comparison"] == "compared_value"]
    assert [c["value"] for c in compared_iss] == ["2026-11-05", "2026-11-11"]

    # Exceeding spread / competing same-kind documents -> CONFLITO
    d_old = _make_doc("doc-old", DocumentKind.LAUDO.value, fields=_complete_fields("ver-doc-old-1", issue_date="2026-09-01"))
    d_new = _make_doc("doc-new", DocumentKind.LAUDO.value, fields=_complete_fields("ver-doc-new-1", issue_date="2026-11-11"))
    res_competing = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d_old, d_new))
    )
    assert res_competing.axes[AxisName.TEMPORALIDADE].status == AxisStatus.CONFLITO

    # Superseded v1 preserves lineage while v2 regression (earlier issue_date on v2) triggers CONFLITO
    v1_old = DocumentVersionInput(
        version_id="ver-sup-1",
        document_id="doc-2",
        version_number=1,
        sha256_hex="e" * 64,
        mime_type="application/pdf",
        created_at=_BASE_TS - timedelta(days=1),
        is_current=False,
        superseded_by_version_id="ver-doc-2-2",
        integrity_status=ProcessingStatus.SUCCEEDED.value,
        extraction_run_id="run-old",
        extraction_status=ProcessingStatus.SUCCEEDED.value,
        extractor_version="pdfminer-deterministic-3.3.3",
        extraction_readable=True,
        extraction_outcome="extracted",
        extracted_fields=tuple(_complete_fields("ver-sup-1", issue_date="2026-11-12")),
    )
    d2_regressed = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        ver_id="ver-doc-2-2",
        version_number=2,
        fields=_complete_fields("ver-doc-2-2", issue_date="2026-11-08"),
        extra_versions=(v1_old,),
    )
    res_reg = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1, d2_regressed))
    )
    assert res_reg.axes[AxisName.TEMPORALIDADE].status == AxisStatus.CONFLITO
    assert res_reg.axes[AxisName.TEMPORALIDADE].rule_code == "TEMPORALITY_VERSION_DATE_REGRESSION"

    # Invalid issue date -> ABSTENCAO; Missing issue date -> PENDENTE
    f_bad_date = [
        x
        if x.field_key != "issue_date"
        else _field(
            "bad-iss",
            "issue_date",
            "31/02/2026",
            None,
            ver_id="ver-doc-2-1",
            status=ExtractedFieldStatus.ABSTAINED.value,
            abstained=True,
        )
        for x in _complete_fields("ver-doc-2-1")
    ]
    res_baddate = evaluate_case_consistency(
        CaseConsistencyInput(
            organization_id="org-1",
            case_id="c1",
            case_code="C1",
            documents=(d1, _make_doc("doc-2", DocumentKind.LAUDO.value, fields=f_bad_date)),
        )
    )
    assert res_baddate.axes[AxisName.TEMPORALIDADE].status == AxisStatus.ABSTENCAO

    # Invalid evidence (missing/corrupt bbox or cross-version) -> ABSTENCAO across axes!
    f_invalid_ev = [
        x
        if x.field_key != "issue_date"
        else _field(
            "inv-iss",
            "issue_date",
            "11/11/2026",
            "2026-11-11",
            ver_id="ver-doc-2-1",
            bbox=(1.2, 0.2, 0.3, 0.05),
        )
        for x in _complete_fields("ver-doc-2-1")
    ]
    res_invev = evaluate_case_consistency(
        CaseConsistencyInput(
            organization_id="org-1",
            case_id="c1",
            case_code="C1",
            documents=(d1, _make_doc("doc-2", DocumentKind.LAUDO.value, fields=f_invalid_ev)),
        )
    )
    assert res_invev.axes[AxisName.TEMPORALIDADE].status == AxisStatus.ABSTENCAO
    assert res_invev.axes[AxisName.TEMPORALIDADE].rule_code == "TEMPORALITY_INVALID_EVIDENCE"

    # Multiple conflicts simultaneously (identity + laterality) -> BLOQUEADO preserving both conflicts
    d_multi_conf = _make_doc(
        "doc-2",
        DocumentKind.LAUDO.value,
        fields=_complete_fields("ver-doc-2-1", identifier="SYN-P99", laterality="OE"),
    )
    res_multiconf = evaluate_case_consistency(
        CaseConsistencyInput(organization_id="org-1", case_id="c1", case_code="C1", documents=(d1, d_multi_conf))
    )
    assert res_multiconf.axes[AxisName.IDENTIDADE].status == AxisStatus.CONFLITO
    assert res_multiconf.axes[AxisName.LATERALIDADE].status == AxisStatus.CONFLITO
    assert res_multiconf.readiness_state == CaseReadinessState.BLOQUEADO

    # Reference date policy check deterministically catches stale document > max_age_days
    res_stale = evaluate_case_consistency(
        CaseConsistencyInput(
            organization_id="org-1",
            case_id="c1",
            case_code="C1",
            max_issue_date_spread_days=30,
            reference_date=date(2026, 12, 20),
            documents=(d1, _make_doc("doc-2", DocumentKind.LAUDO.value, fields=_complete_fields("ver-doc-2-1"))),
        )
    )
    assert res_stale.axes[AxisName.TEMPORALIDADE].status == AxisStatus.CONFLITO
    assert res_stale.axes[AxisName.TEMPORALIDADE].rule_code == "TEMPORALITY_STALE_ISSUE_DATE_EXCEEDS_POLICY"


# =============================================================================
# 2. Full End-to-End Pipeline + API + RLS + Worker + Idempotency + Benchmark
# =============================================================================


def _seed_api_environment(migrated_engine, app_engine, tmp_path: Path) -> dict[str, Any]:
    owner_factory = create_session_factory(migrated_engine)
    app_factory = create_session_factory(app_engine)
    storage_root = tmp_path / "storage"
    storage_root.mkdir(parents=True, exist_ok=True)
    db_url = str(app_engine.url.render_as_string(hide_password=False))
    settings = Settings(
        env="test",
        database_url=db_url,
        worker_database_url=db_url,
        migration_database_url=str(migrated_engine.url.render_as_string(hide_password=False)),
        storage_root=storage_root.as_posix(),
        allow_local_synthetic_storage=True,
        app_base_url="http://127.0.0.1:8000",
        cors_allowed_origins=("http://127.0.0.1:8000",),
        session_cookie_secure=False,
        worker_poll_interval_seconds=0.05,
        worker_lease_seconds=30,
        worker_max_attempts=3,
        worker_retry_backoff_min_seconds=0.1,
        worker_retry_backoff_max_seconds=0.5,
        worker_retry_jitter_ratio=0.0,
    )

    owner_db = owner_factory()
    now = datetime.now(timezone.utc)
    try:
        org_a = OrganizationRepository.create_organization(owner_db, slug="cons-a", name="Consistency Org A")
        org_b = OrganizationRepository.create_organization(owner_db, slug="cons-b", name="Consistency Org B")
        actors: dict[str, dict[str, str]] = {}
        for role_key, role_enum, target_org in (
            ("admin_a", OrganizationRole.ORG_ADMIN, org_a),
            ("reviewer_a", OrganizationRole.DOCUMENT_REVIEWER, org_a),
            ("auditor_a", OrganizationRole.AUDITOR_READONLY, org_a),
            ("admin_b", OrganizationRole.ORG_ADMIN, org_b),
        ):
            user = OrganizationRepository.create_user(
                owner_db,
                email=f"{role_key}@jyxia.local",
                display_name=role_key,
                mfa_enrolled=True,
            )
            OrganizationRepository.assign_membership(
                owner_db,
                TenantContext(organization_id=target_org.id),
                user_id=user.id,
                role=role_enum.value,
            )
            ext = IdentityAndSessionRepository.bind_external_identity(
                owner_db,
                user_id=user.id,
                issuer="https://idp.jyxia.local/realms/cons",
                subject=f"sub-{role_key}",
                email_at_binding=user.email,
            )
            raw_tok = generate_opaque_token()
            raw_csrf = generate_opaque_token()
            tok_hash = hmac_token_digest(raw_tok, secret=settings.session_secret, context="session_token")
            csrf_hash = hmac_token_digest(raw_csrf, secret=settings.csrf_secret, context="csrf_token")
            IdentityAndSessionRepository.create_auth_session(
                owner_db,
                user_id=user.id,
                external_identity_id=ext.id,
                active_organization_id=target_org.id,
                session_token_hash=tok_hash,
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
            actors[role_key] = {
                "user_id": user.id,
                "session_cookie": raw_tok,
                "csrf_cookie": raw_csrf,
                "org_id": target_org.id,
            }
        case_b = CaseAndDocumentRepository.create_case(
            owner_db,
            TenantContext(organization_id=org_b.id, actor_user_id=actors["admin_b"]["user_id"]),
            case_code="CONS-B-01",
            external_reference=None,
            procedure_reference="Tenant B Isolated Case",
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        owner_db.commit()
        org_a_id, org_b_id, case_b_id = org_a.id, org_b.id, case_b.id
    finally:
        owner_db.close()

    return {
        "settings": settings,
        "storage_root": storage_root,
        "org_a_id": org_a_id,
        "org_b_id": org_b_id,
        "case_b_id": case_b_id,
        "actors": actors,
        "app_factory": app_factory,
    }


def _build_rotated_cropbox_pdf(lines_with_coords: list[tuple[int, int, str]]) -> bytes:
    """Build single-page rotated (Rotate=90) PDF with non-zero CropBox for coordinate parity verification."""
    ops = ["BT /F1 11 Tf"]
    for x, y, txt in lines_with_coords:
        esc = txt.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
        ops.append(f"1 0 0 1 {x} {y} Tm ({esc}) Tj")
    ops.append("ET")
    stream = ("\n".join(ops) + "\n").encode("latin1")
    objs = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 600 800] /CropBox [20 40 580 780] /Rotate 90 /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        f"5 0 obj\n<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"endstream\nendobj\n",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offs = [0]
    for obj in objs:
        offs.append(len(out))
        out.extend(obj)
    xref = len(out)
    out.extend(f"xref\n0 {len(offs)}\n0000000000 65535 f \n".encode("ascii"))
    for o in offs[1:]:
        out.extend(f"{o:010d} 00000 n \n".encode("ascii"))
    out.extend(f"trailer\n<< /Size {len(offs)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(out)


def test_end_to_end_pipeline_benchmark_with_15_fixtures_history_and_rls(
    migrated_engine, app_engine, worker_engine, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env = _seed_api_environment(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    storage = LocalControlledSyntheticStorage(env["storage_root"], enabled=True, max_bytes=20 * 1024 * 1024)
    org_a_id = env["org_a_id"]
    org_b_id = env["org_b_id"]
    case_b_id = env["case_b_id"]
    worker = ProcessingWorker(create_session_factory(worker_engine), storage, env["settings"], worker_id="bench-wrk")

    def _create_and_upload(
        client: TestClient, case_code: str, docs: list[tuple[str, DocumentKind, bytes, str]]
    ) -> tuple[str, list[dict[str, Any]]]:
        headers = {CSRF_HEADER_NAME: env["actors"]["admin_a"]["csrf_cookie"], "Origin": "http://127.0.0.1:8000"}
        seed_db = create_session_factory(migrated_engine)()
        try:
            case_obj = CaseAndDocumentRepository.create_case(
                seed_db,
                TenantContext(organization_id=org_a_id, actor_user_id=env["actors"]["admin_a"]["user_id"]),
                case_code=case_code,
                external_reference=None,
                procedure_reference=f"Bench {case_code}",
                declared_laterality=None,
                readiness_state=CaseReadinessState.PENDENTE.value,
            )
            seed_db.commit()
            case_id = case_obj.id
        finally:
            seed_db.close()

        uploaded: list[dict[str, Any]] = []
        for fname, kind, content, mime in docs:
            u_resp = client.post(
                f"/api/v1/organizations/{org_a_id}/cases/{case_id}/documents",
                headers=headers,
                data={"document_kind": kind.value, "source_label": f"bench:{fname}"},
                files={"file": (fname, content, mime)},
            )
            assert u_resp.status_code == 201
            uploaded.append(u_resp.json())
        return case_id, uploaded

    # Load ALL 15 PDFs + 1 unreadable PNG into controlled cases
    fixture_bytes = {p.name: p.read_bytes() for p in sorted(FIXTURES_DIR.glob("*.pdf"))}
    assert len(fixture_bytes) == 15
    png_bytes = (FIXTURES_DIR / "imagem-ilegivel.png").read_bytes()

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin_a"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin_a"]["csrf_cookie"])

        # Case 1: Complete coherent 4-axis quartet
        c1_id, _ = _create_and_upload(
            client,
            "BENCH-COHERENT",
            [
                ("solicitacao-completa.pdf", DocumentKind.PEDIDO, fixture_bytes["solicitacao-completa.pdf"], "application/pdf"),
                ("laudo-completo.pdf", DocumentKind.LAUDO, fixture_bytes["laudo-completo.pdf"], "application/pdf"),
                ("avaliacao-completa.pdf", DocumentKind.LAUDO, fixture_bytes["avaliacao-completa.pdf"], "application/pdf"),
                ("termo-completo.pdf", DocumentKind.TERMO, fixture_bytes["termo-completo.pdf"], "application/pdf"),
            ],
        )
        # Case 2: Explicit laterality conflict OD vs OE
        c2_id, _ = _create_and_upload(
            client,
            "BENCH-LAT-CONFLICT",
            [
                ("solicitacao-od.pdf", DocumentKind.PEDIDO, fixture_bytes["solicitacao-od.pdf"], "application/pdf"),
                ("termo-oe.pdf", DocumentKind.TERMO, fixture_bytes["termo-oe.pdf"], "application/pdf"),
            ],
        )
        # Case 3: Identity conflict
        c3_id, _ = _create_and_upload(
            client,
            "BENCH-ID-CONFLICT",
            [
                ("solicitacao-completa.pdf", DocumentKind.PEDIDO, fixture_bytes["solicitacao-completa.pdf"], "application/pdf"),
                ("identidade-divergente.pdf", DocumentKind.LAUDO, fixture_bytes["identidade-divergente.pdf"], "application/pdf"),
            ],
        )
        # Case 4: Missing identifier -> Identidade PENDENTE
        c4_id, _ = _create_and_upload(
            client,
            "BENCH-MISSING-ID",
            [
                ("laudo.pdf", DocumentKind.LAUDO, fixture_bytes["laudo.pdf"], "application/pdf"),
                ("sem-identificador.pdf", DocumentKind.LAUDO, fixture_bytes["sem-identificador.pdf"], "application/pdf"),
            ],
        )
        # Case 5: Missing procedure & laterality historical files -> PENDENTE
        c5_id, _ = _create_and_upload(
            client,
            "BENCH-PARTIAL-HIST",
            [
                ("solicitacao.pdf", DocumentKind.PEDIDO, fixture_bytes["solicitacao.pdf"], "application/pdf"),
                ("avaliacao.pdf", DocumentKind.LAUDO, fixture_bytes["avaliacao.pdf"], "application/pdf"),
                ("termo-sem-marca.pdf", DocumentKind.TERMO, fixture_bytes["termo-sem-marca.pdf"], "application/pdf"),
                ("termo.pdf", DocumentKind.TERMO, fixture_bytes["termo.pdf"], "application/pdf"),
            ],
        )
        # Case 6: Competing active dates same kind (laudo-antigo 16/10 vs laudo-atualizado 14/11) -> CONFLITO
        c6_id, _ = _create_and_upload(
            client,
            "BENCH-TEMP-COMPETE",
            [
                ("laudo-antigo.pdf", DocumentKind.LAUDO, fixture_bytes["laudo-antigo.pdf"], "application/pdf"),
                ("laudo-atualizado.pdf", DocumentKind.LAUDO, fixture_bytes["laudo-atualizado.pdf"], "application/pdf"),
            ],
        )
        # Case 7: Unreadable PNG -> ABSTENCAO
        c7_id, _ = _create_and_upload(
            client,
            "BENCH-UNREADABLE",
            [
                ("solicitacao.pdf", DocumentKind.PEDIDO, fixture_bytes["solicitacao.pdf"], "application/pdf"),
                ("imagem-ilegivel.png", DocumentKind.IMAGEM, png_bytes, "image/png"),
            ],
        )

    # Process all verify + extract + barrier-chained compare_consistency jobs across cycles
    for _ in range(8):
        if worker.process_one_cycle(max_jobs=30).claimed == 0:
            break

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["auditor_a"]["session_cookie"])

        def _get_latest_detail(cid: str) -> dict[str, Any]:
            lst = client.get(f"/api/v1/organizations/{org_a_id}/cases/{cid}/consistency-assessments")
            assert lst.status_code == 200
            assert "no-store" in lst.headers.get("Cache-Control", "")
            payload = lst.json()
            assert payload["total"] >= 1
            aid = payload["assessments"][0]["assessment_id"]
            det = client.get(f"/api/v1/organizations/{org_a_id}/cases/{cid}/consistency-assessments/{aid}")
            assert det.status_code == 200
            assert "no-store" in det.headers.get("Cache-Control", "")
            return det.json()

        d_coherent = _get_latest_detail(c1_id)
        assert all(ax["status"] == AxisStatus.OK.value for ax in d_coherent["axes"])
        assert d_coherent["automated_axes_outcome"] == "all_ok"
        assert d_coherent["human_review_completed"] is False
        assert d_coherent["readiness_state"] == CaseReadinessState.PENDENTE.value
        assert d_coherent["clinical_approval"] is False
        assert d_coherent["administrative_only"] is True
        assert d_coherent["summary"]["clinical_decision"]["out_of_scope"] is True

        d_lat = _get_latest_detail(c2_id)
        lat_ax = {a["axis"]: a for a in d_lat["axes"]}[AxisName.LATERALIDADE.value]
        assert lat_ax["status"] == AxisStatus.CONFLITO.value
        assert lat_ax["rule"] == "EXPLICIT_LATERALITY_MISMATCH"
        assert {c["value"] for c in lat_ax["comparison"] if c["value"]} == {"OD", "OE"}
        assert all(len(c["bbox"]) == 4 and c["page"] == 1 and c["evidence_id"] for c in lat_ax["comparison"] if c["evidence_id"])
        assert d_lat["readiness_state"] == CaseReadinessState.BLOQUEADO.value

        d_id = _get_latest_detail(c3_id)
        id_ax = {a["axis"]: a for a in d_id["axes"]}[AxisName.IDENTIDADE.value]
        assert id_ax["status"] == AxisStatus.CONFLITO.value
        assert id_ax["rule"] == "IDENTITY_IDENTIFIER_CONFLICT"
        assert d_id["readiness_state"] == CaseReadinessState.BLOQUEADO.value

        d_miss = _get_latest_detail(c4_id)
        assert {a["axis"]: a["status"] for a in d_miss["axes"]}[AxisName.IDENTIDADE.value] == AxisStatus.PENDENTE.value

        d_hist = _get_latest_detail(c5_id)
        hist_statuses = {a["axis"]: a["status"] for a in d_hist["axes"]}
        assert hist_statuses[AxisName.IDENTIDADE.value] == AxisStatus.OK.value
        assert hist_statuses[AxisName.PROCEDIMENTO_CODIGO.value] == AxisStatus.PENDENTE.value
        assert hist_statuses[AxisName.LATERALIDADE.value] == AxisStatus.PENDENTE.value
        assert d_hist["readiness_state"] == CaseReadinessState.PENDENTE.value

        d_temp = _get_latest_detail(c6_id)
        assert {a["axis"]: a["status"] for a in d_temp["axes"]}[AxisName.TEMPORALIDADE.value] == AxisStatus.CONFLITO.value
        assert d_temp["readiness_state"] == CaseReadinessState.BLOQUEADO.value

        d_unr = _get_latest_detail(c7_id)
        assert d_unr["readiness_state"] == CaseReadinessState.ABSTENCAO.value

        # RBAC check: AUDITOR_READONLY can GET, CANNOT POST new compare run -> 403 Forbidden
        r_forbid = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{c1_id}/consistency-assessments",
            headers={CSRF_HEADER_NAME: env["actors"]["auditor_a"]["csrf_cookie"], "Origin": "http://127.0.0.1:8000"},
        )
        assert r_forbid.status_code == 403

        # Cross-tenant UUID isolation check (Org B admin tries to read Org A assessment -> 404, never leaks!)
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin_b"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin_b"]["csrf_cookie"])
        assert (
            client.get(
                f"/api/v1/organizations/{org_b_id}/cases/{c1_id}/consistency-assessments/{d_coherent['assessment_id']}"
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/organizations/{org_b_id}/cases/{case_b_id}/consistency-assessments/{d_coherent['assessment_id']}"
            ).status_code
            == 404
        )
        assert (
            client.get(
                f"/api/v1/organizations/{org_a_id}/cases/{c1_id}/consistency-assessments/{d_coherent['assessment_id']}"
            ).status_code
            == 403
        )
        # HTTP mutation attempts rejected cleanly
        assert (
            client.delete(
                f"/api/v1/organizations/{org_a_id}/cases/{c1_id}/consistency-assessments/{d_coherent['assessment_id']}",
                headers={CSRF_HEADER_NAME: env["actors"]["admin_b"]["csrf_cookie"], "Origin": "http://127.0.0.1:8000"},
            ).status_code
            == 405
        )

    # Retry & Commit Rollback Idempotency + New Engine Version Historical Preservation
    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["reviewer_a"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["reviewer_a"]["csrf_cookie"])
        rev_headers = {CSRF_HEADER_NAME: env["actors"]["reviewer_a"]["csrf_cookie"], "Origin": "http://127.0.0.1:8000"}
        re_1 = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{c1_id}/consistency-assessments",
            headers={**rev_headers, IDEMPOTENCY_KEY_HEADER_NAME: "recheck-334"},
        )
        re_replay = client.post(
            f"/api/v1/organizations/{org_a_id}/cases/{c1_id}/consistency-assessments",
            headers={**rev_headers, IDEMPOTENCY_KEY_HEADER_NAME: "recheck-334"},
        )
        assert re_1.status_code == 201 and re_replay.status_code == 200
        assert re_1.json()["processing_run_id"] == re_replay.json()["processing_run_id"]

    # Simulate crash BEFORE commit inside complete_comparison_run -> ZERO partial rows, then recover cleanly!
    orig_complete_cmp = ProcessingQueueRepository.complete_comparison_run

    def _boom_cmp(*_args, **_kwargs):
        raise LeaseOwnershipError("Simulated crash before committing assessment")

    monkeypatch.setattr(ProcessingQueueRepository, "complete_comparison_run", staticmethod(_boom_cmp))
    crash_stats = worker.process_one_cycle(max_jobs=5)
    assert crash_stats.lease_lost == 1
    monkeypatch.setattr(ProcessingQueueRepository, "complete_comparison_run", staticmethod(orig_complete_cmp))

    # Expire lease on re_1 run & re-run -> succeeds WITHOUT duplicate rows and preserves assessment #1!
    owner_exp = create_session_factory(migrated_engine)()
    try:
        apply_pg_rls_context(owner_exp, organization_id=org_a_id)
        owner_exp.execute(
            text("UPDATE processing_runs SET lease_expires_at = :exp WHERE id = :rid"),
            {"exp": datetime.now(timezone.utc) - timedelta(seconds=30), "rid": re_1.json()["processing_run_id"]},
        )
        owner_exp.commit()
    finally:
        owner_exp.close()

    assert worker.process_one_cycle(max_jobs=5).succeeded == 1

    # Also run with NEW engine_version ("3.3.5") -> preserves previous assessments and creates #3!
    settings_v2 = env["settings"].model_copy(update={"consistency_engine_version": "3.3.5"})
    app_v2 = create_app(settings_v2)
    w_v2 = ProcessingWorker(create_session_factory(worker_engine), storage, settings_v2, worker_id="wrk-335")
    with TestClient(app_v2) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["reviewer_a"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["reviewer_a"]["csrf_cookie"])
        assert (
            client.post(
                f"/api/v1/organizations/{org_a_id}/cases/{c1_id}/consistency-assessments",
                headers={CSRF_HEADER_NAME: env["actors"]["reviewer_a"]["csrf_cookie"], "Origin": "http://127.0.0.1:8000"},
            ).status_code
            == 201
        )
    assert w_v2.process_one_cycle(max_jobs=5).succeeded == 1

    with TestClient(app_v2) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["reviewer_a"]["session_cookie"])
        hist = client.get(f"/api/v1/organizations/{org_a_id}/cases/{c1_id}/consistency-assessments").json()
        assert hist["total"] == 3
        assert [a["assessment_sequence"] for a in hist["assessments"]] == [3, 2, 1]
        assert hist["assessments"][0]["engine_version"] == "3.3.5"
        assert hist["assessments"][1]["input_fingerprint_sha256"] == hist["assessments"][2]["input_fingerprint_sha256"]

    # Append-only immutability check on ORM + RLS verification
    owner_chk = create_session_factory(migrated_engine)()
    try:
        apply_pg_rls_context(owner_chk, organization_id=org_a_id)
        assess_row = owner_chk.execute(
            text("SELECT id FROM consistency_assessments WHERE organization_id = :org LIMIT 1"),
            {"org": org_a_id},
        ).scalar_one()
        orm_row = owner_chk.get(ConsistencyAssessment, assess_row)
        assert orm_row is not None
        orm_row.readiness_state = CaseReadinessState.CONFERIDA.value
        with pytest.raises(ValueError, match="append-only"):
            owner_chk.flush()
        owner_chk.rollback()

        if app_engine.dialect.name == "postgresql":
            with create_session_factory(app_engine)() as app_db:
                clear_pg_rls_context(app_db)
                assert (
                    app_db.execute(text("SELECT COUNT(*) FROM consistency_assessments")).scalar() == 0
                )
                apply_pg_rls_context(app_db, organization_id=org_b_id)
                assert (
                    app_db.execute(
                        text("SELECT COUNT(*) FROM consistency_assessments WHERE id = :id"),
                        {"id": assess_row},
                    ).scalar()
                    == 0
                )

        # Record human reviews across active versions of BENCH-COHERENT -> transitions to CONFERIDA (#4)
        ver_ids_c1 = [item["version_id"] for item in d_coherent["compared_snapshot"] if item["version_id"]]
        ax_row_id = owner_chk.execute(
            text("SELECT id FROM consistency_axis_results WHERE assessment_id = :aid LIMIT 1"),
            {"aid": d_coherent["assessment_id"]},
        ).scalar_one()
        other_ver_id = owner_chk.execute(
            text("SELECT id FROM document_versions WHERE organization_id = :org AND id <> :v1 LIMIT 1"),
            {"org": org_a_id, "v1": ver_ids_c1[0]},
        ).scalar_one()
        ev_from_v1 = owner_chk.execute(
            text(
                "SELECT id, extracted_field_id FROM evidence_references "
                "WHERE organization_id = :org AND document_version_id = :v1 LIMIT 1"
            ),
            {"org": org_a_id, "v1": ver_ids_c1[0]},
        ).first()
        assert ev_from_v1 is not None
        # DB composite FK MUST block linking EvidenceReference of v1 with document_version_id = other_ver_id
        owner_chk.add(
            ConsistencyAxisEvidence(
                organization_id=org_a_id,
                assessment_id=d_coherent["assessment_id"],
                axis_result_id=ax_row_id,
                document_version_id=other_ver_id,
                extracted_field_id=ev_from_v1[1],
                evidence_reference_id=ev_from_v1[0],
            )
        )
        with pytest.raises(IntegrityError):
            owner_chk.flush()
        owner_chk.rollback()

        apply_pg_rls_context(owner_chk, organization_id=org_a_id)
        for v_id in ver_ids_c1:
            InstitutionalService.record_human_review(
                owner_chk,
                TenantContext(organization_id=org_a_id, actor_user_id=env["actors"]["reviewer_a"]["user_id"]),
                HumanReviewCreateInput(
                    document_version_id=v_id,
                    reviewer_user_id=env["actors"]["reviewer_a"]["user_id"],
                    action_type=HumanReviewAction.OBSERVED,
                    justification="Conferencia administrativa de campos e evidencias no caso BENCH-COHERENT.",
                    policy_version="3.3.4",
                ),
            )
        owner_chk.commit()
    finally:
        owner_chk.close()

    with TestClient(app_v2) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["reviewer_a"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["reviewer_a"]["csrf_cookie"])
        assert (
            client.post(
                f"/api/v1/organizations/{org_a_id}/cases/{c1_id}/consistency-assessments",
                headers={CSRF_HEADER_NAME: env["actors"]["reviewer_a"]["csrf_cookie"], "Origin": "http://127.0.0.1:8000"},
            ).status_code
            == 201
        )
    assert w_v2.process_one_cycle(max_jobs=5).succeeded == 1
    with TestClient(app_v2) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["reviewer_a"]["session_cookie"])
        reviewed_hist = client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{c1_id}/consistency-assessments"
        ).json()
        assert reviewed_hist["total"] == 4
        assert reviewed_hist["assessments"][0]["human_review_completed"] is True
        assert reviewed_hist["assessments"][0]["readiness_state"] == CaseReadinessState.CONFERIDA.value
        assert reviewed_hist["assessments"][0]["clinical_approval"] is False


def test_rotated_cropbox_pdfs_and_audit_zero_pii(
    migrated_engine, app_engine, worker_engine, tmp_path: Path
) -> None:
    env = _seed_api_environment(migrated_engine, app_engine, tmp_path)
    app = create_app(env["settings"])
    storage = LocalControlledSyntheticStorage(env["storage_root"], enabled=True, max_bytes=20 * 1024 * 1024)
    org_a_id = env["org_a_id"]
    worker = ProcessingWorker(create_session_factory(worker_engine), storage, env["settings"], worker_id="rot-wrk")

    pdf_od = _build_rotated_cropbox_pdf(
        [
            (60, 700, "Paciente: Pessoa Rotacionada Alfa"),
            (60, 675, "Nascimento: 12/04/1986"),
            (60, 650, "Identificador: SYN-P99"),
            (60, 625, "Emissao: 11/11/2026"),
            (60, 600, "Procedimento: Facoemulsificacao com implante de LIO"),
            (60, 575, "Sistema: SIGTAP-FICTICIO"),
            (60, 550, "Codigo: 04.05.05.011-9"),
            (60, 525, "Lateralidade: Olho Direito (OD)"),
        ]
    )
    pdf_oe = _build_rotated_cropbox_pdf(
        [
            (60, 700, "Paciente: Pessoa Rotacionada Alfa"),
            (60, 675, "Nascimento: 12/04/1986"),
            (60, 650, "Identificador: SYN-P99"),
            (60, 625, "Emissao: 11/11/2026"),
            (60, 600, "Procedimento: Facoemulsificacao com implante de LIO"),
            (60, 575, "Sistema: SIGTAP-FICTICIO"),
            (60, 550, "Codigo: 04.05.05.011-9"),
            (60, 525, "Lateralidade: Olho Esquerdo (OE)"),
        ]
    )

    seed_db = create_session_factory(migrated_engine)()
    try:
        case_obj = CaseAndDocumentRepository.create_case(
            seed_db,
            TenantContext(organization_id=org_a_id, actor_user_id=env["actors"]["admin_a"]["user_id"]),
            case_code="ROT-CROP-01",
            external_reference=None,
            procedure_reference="Rotated CropBox Check",
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        seed_db.commit()
        case_id = case_obj.id
    finally:
        seed_db.close()

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["admin_a"]["session_cookie"])
        client.cookies.set(CSRF_COOKIE_NAME, env["actors"]["admin_a"]["csrf_cookie"])
        headers = {CSRF_HEADER_NAME: env["actors"]["admin_a"]["csrf_cookie"], "Origin": "http://127.0.0.1:8000"}
        for idx, b in enumerate((pdf_od, pdf_oe)):
            r = client.post(
                f"/api/v1/organizations/{org_a_id}/cases/{case_id}/documents",
                headers=headers,
                data={"document_kind": DocumentKind.LAUDO.value, "source_label": f"rot_{idx}"},
                files={"file": (f"rot-{idx}.pdf", b, "application/pdf")},
            )
            assert r.status_code == 201

    assert worker.process_one_cycle(max_jobs=10).succeeded == 5

    with TestClient(app) as client:
        client.cookies.set(SESSION_COOKIE_NAME, env["actors"]["reviewer_a"]["session_cookie"])
        lst = client.get(f"/api/v1/organizations/{org_a_id}/cases/{case_id}/consistency-assessments").json()
        det = client.get(
            f"/api/v1/organizations/{org_a_id}/cases/{case_id}/consistency-assessments/{lst['assessments'][0]['assessment_id']}"
        ).json()
        by_ax = {a["axis"]: a for a in det["axes"]}
        assert by_ax[AxisName.LATERALIDADE.value]["status"] == AxisStatus.CONFLITO.value
        assert by_ax[AxisName.IDENTIDADE.value]["status"] == AxisStatus.OK.value
        for item in by_ax[AxisName.LATERALIDADE.value]["comparison"]:
            bx = item["bbox"]
            assert bx is not None and len(bx) == 4
            assert 0.0 <= bx[0] <= 1.0 and 0.0 <= bx[1] <= 1.0 and bx[0] + bx[2] <= 1.00001 and bx[1] + bx[3] <= 1.00001

    # Verify audit chain valid and ZERO PII or raw field quotes leaked into audit_events
    owner_db = create_session_factory(migrated_engine)()
    try:
        events = AuditEventRepository.list_events(owner_db, TenantContext(organization_id=org_a_id))
        assert AuditEventRepository.verify_chain_detailed(owner_db, TenantContext(organization_id=org_a_id)).valid
        serialized = json.dumps([e.payload_json for e in events])
        assert "Pessoa Rotacionada Alfa" not in serialized
        assert "Olho Direito" not in serialized
    finally:
        owner_db.close()
