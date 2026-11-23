"""RBAC-protected and tenant-isolated processing queue consultation and reprocessing routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_db_session,
    require_csrf_protection,
    require_org_permission,
)
from app.core.constants import IDEMPOTENCY_KEY_HEADER_NAME
from app.core.rbac import RbacPermission
from app.models.entities import EvidenceReference, ExtractedField, ProcessingRun
from app.schemas.auth import (
    CaseProcessingRunsListResponse,
    EvidenceReferencesListResponse,
    EvidenceReferenceSummaryResponse,
    ExtractedFieldItemResponse,
    ExtractedFieldsListResponse,
    ProcessingRunSummaryResponse,
)
from app.schemas.tenant import TenantContext, validate_safe_metadata_text
from app.services.auth_service import AuthorizedMembershipContext
from app.services.institutional_service import (
    DocumentNotFoundError,
    IdempotencyConflictError,
    InstitutionalService,
    ProcessingRunActiveConflictError,
)

router = APIRouter(prefix="/organizations", tags=["processing"])

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}


def _set_no_store(response: Response) -> None:
    for key, val in _NO_STORE_HEADERS.items():
        response.headers[key] = val


def _to_tenant_ctx(auth_ctx: AuthorizedMembershipContext) -> TenantContext:
    return TenantContext(
        organization_id=auth_ctx.principal.organization_id,
        actor_user_id=auth_ctx.principal.user_id,
        session_token_hash=auth_ctx.principal.session.session_token_hash,
        source="authenticated_request",
    )


def to_processing_run_summary(
    run: ProcessingRun,
    *,
    document_id: str | None = None,
    case_id: str | None = None,
) -> ProcessingRunSummaryResponse:
    """Serialize ProcessingRun safely without exposing lease hashes, worker secrets, or storage keys."""
    return ProcessingRunSummaryResponse(
        processing_run_id=run.id,
        organization_id=run.organization_id,
        document_version_id=run.document_version_id,
        document_id=document_id,
        case_id=case_id,
        step_type=run.step_type,
        status=run.status,
        policy_version=run.policy_version,
        extractor_version=run.extractor_version,
        attempt_count=run.attempt_count,
        max_attempts=run.max_attempts,
        available_at=run.available_at,
        started_at=run.started_at,
        finished_at=run.finished_at,
        created_at=run.created_at,
        updated_at=run.updated_at,
        last_error_code=run.last_error_code,
        last_error_detail=run.last_error_detail,
        result_json=run.result_json,
        readable=run.readable,
        readiness_state=run.readiness_state,
        administrative_only=True,
        clinical_approval=False,
    )


@router.get(
    "/{organization_id}/cases/{case_id}/processing-runs",
    response_model=CaseProcessingRunsListResponse,
)
def list_case_processing_runs(
    organization_id: str,
    case_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
    document_version_id: Annotated[str | None, Query(min_length=1, max_length=36)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> CaseProcessingRunsListResponse:
    _ = organization_id
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        page = InstitutionalService.list_case_processing_runs(
            session,
            ctx,
            case_id=case_id,
            document_version_id=document_version_id,
            limit=limit,
            offset=offset,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return CaseProcessingRunsListResponse(
        organization_id=ctx.organization_id,
        case_id=page.case.id,
        total=page.total,
        limit=page.limit,
        offset=page.offset,
        processing_runs=[
            to_processing_run_summary(run, document_id=doc_id, case_id=item_case_id)
            for run, doc_id, item_case_id in page.items
        ],
    )


@router.get(
    "/{organization_id}/processing-runs/{processing_run_id}",
    response_model=ProcessingRunSummaryResponse,
)
def get_organization_processing_run(
    organization_id: str,
    processing_run_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
) -> ProcessingRunSummaryResponse:
    _ = organization_id
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        detail = InstitutionalService.get_processing_run(
            session,
            ctx,
            processing_run_id=processing_run_id,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return to_processing_run_summary(
        detail.processing_run,
        document_id=detail.document_id,
        case_id=detail.case_id,
    )


@router.post(
    "/{organization_id}/documents/{document_id}/versions/{version_id}/reprocess",
    response_model=ProcessingRunSummaryResponse,
    status_code=201,
)
def enqueue_document_version_reprocessing(
    organization_id: str,
    document_id: str,
    version_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_UPLOAD)),
    ],
    _csrf: Annotated[None, Depends(require_csrf_protection)],
    idempotency_key: Annotated[
        str | None, Header(alias=IDEMPOTENCY_KEY_HEADER_NAME)
    ] = None,
) -> ProcessingRunSummaryResponse:
    _ = organization_id
    _set_no_store(response)
    if idempotency_key is not None:
        try:
            idempotency_key = validate_safe_metadata_text(
                idempotency_key,
                field_name="Idempotency-Key",
                min_len=4,
                max_len=128,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    ctx = _to_tenant_ctx(auth_ctx)
    try:
        detail = InstitutionalService.enqueue_document_version_reprocessing(
            session,
            ctx,
            document_id=document_id,
            version_id=version_id,
            idempotency_key=idempotency_key,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ProcessingRunActiveConflictError, IdempotencyConflictError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc

    response.status_code = 200 if detail.idempotent_replay else 201
    return to_processing_run_summary(
        detail.processing_run,
        document_id=detail.document_id,
        case_id=detail.case_id,
    )


def _to_evidence_summary(
    ev: EvidenceReference,
    *,
    field: ExtractedField,
    run: ProcessingRun,
    document_id: str,
    source_sha256_hex: str,
) -> EvidenceReferenceSummaryResponse:
    return EvidenceReferenceSummaryResponse(
        evidence_reference_id=ev.id,
        organization_id=ev.organization_id,
        extracted_field_id=ev.extracted_field_id,
        field_key=field.field_key,
        document_id=document_id,
        document_version_id=ev.document_version_id,
        source_sha256_hex=source_sha256_hex,
        processing_run_id=run.id,
        extractor_version=run.extractor_version,
        policy_version=run.policy_version,
        page_number=ev.page_number,
        bbox=[round(ev.bbox_x, 6), round(ev.bbox_y, 6), round(ev.bbox_w, 6), round(ev.bbox_h, 6)],
        bbox_x=round(ev.bbox_x, 6),
        bbox_y=round(ev.bbox_y, 6),
        bbox_w=round(ev.bbox_w, 6),
        bbox_h=round(ev.bbox_h, 6),
        quote_excerpt=ev.quote_excerpt,
        extraction_method=ev.extraction_method,
        created_at=ev.created_at,
        administrative_only=True,
        clinical_approval=False,
    )


@router.get(
    "/{organization_id}/documents/{document_id}/versions/{version_id}/extracted-fields",
    response_model=ExtractedFieldsListResponse,
)
def list_document_version_extracted_fields(
    organization_id: str,
    document_id: str,
    version_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
    processing_run_id: Annotated[str | None, Query(min_length=1, max_length=36)] = None,
    latest_only: bool = False,
) -> ExtractedFieldsListResponse:
    _ = organization_id
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        res = InstitutionalService.list_document_version_extracted_fields(
            session,
            ctx,
            document_id=document_id,
            version_id=version_id,
            processing_run_id=processing_run_id,
            latest_only=latest_only,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    latest_outcome: str | None = None
    if res.latest_extract_run and isinstance(res.latest_extract_run.result_json, dict):
        raw_out = res.latest_extract_run.result_json.get("outcome")
        latest_outcome = str(raw_out) if raw_out is not None else None

    fields_out = [
        ExtractedFieldItemResponse(
            extracted_field_id=field_row.id,
            organization_id=field_row.organization_id,
            document_id=res.document.id,
            document_version_id=res.version.id,
            source_sha256_hex=res.version.sha256_hex,
            processing_run_id=run_row.id,
            extractor_version=run_row.extractor_version,
            policy_version=run_row.policy_version,
            field_key=field_row.field_key,
            raw_value=field_row.raw_value,
            normalized_value=field_row.normalized_value,
            status=field_row.status,
            abstained=field_row.abstained,
            metadata_json=field_row.metadata_json,
            evidences=[
                _to_evidence_summary(
                    ev,
                    field=field_row,
                    run=run_row,
                    document_id=res.document.id,
                    source_sha256_hex=res.version.sha256_hex,
                )
                for ev in evidences
            ],
            created_at=field_row.created_at,
            administrative_only=True,
            clinical_approval=False,
        )
        for field_row, run_row, evidences in res.items
    ]

    return ExtractedFieldsListResponse(
        organization_id=ctx.organization_id,
        document_id=res.document.id,
        document_version_id=res.version.id,
        source_sha256_hex=res.version.sha256_hex,
        total=len(fields_out),
        latest_processing_run_id=(
            res.latest_extract_run.id if res.latest_extract_run is not None else None
        ),
        latest_extractor_version=(
            res.latest_extract_run.extractor_version
            if res.latest_extract_run is not None
            else None
        ),
        latest_outcome=latest_outcome,
        extracted_fields=fields_out,
        administrative_only=True,
        clinical_approval=False,
    )


@router.get(
    "/{organization_id}/documents/{document_id}/versions/{version_id}/evidence",
    response_model=EvidenceReferencesListResponse,
)
def list_document_version_evidence(
    organization_id: str,
    document_id: str,
    version_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
    processing_run_id: Annotated[str | None, Query(min_length=1, max_length=36)] = None,
    page_number: Annotated[int | None, Query(ge=1)] = None,
    field_key: Annotated[str | None, Query(min_length=1, max_length=64)] = None,
    latest_only: bool = False,
) -> EvidenceReferencesListResponse:
    _ = organization_id
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        res = InstitutionalService.list_document_version_evidence(
            session,
            ctx,
            document_id=document_id,
            version_id=version_id,
            processing_run_id=processing_run_id,
            page_number=page_number,
            field_key=field_key,
            latest_only=latest_only,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    evidences_out = [
        _to_evidence_summary(
            ev_row,
            field=field_row,
            run=run_row,
            document_id=res.document.id,
            source_sha256_hex=res.version.sha256_hex,
        )
        for ev_row, field_row, run_row in res.items
    ]

    return EvidenceReferencesListResponse(
        organization_id=ctx.organization_id,
        document_id=res.document.id,
        document_version_id=res.version.id,
        source_sha256_hex=res.version.sha256_hex,
        total=len(evidences_out),
        latest_processing_run_id=(
            res.latest_extract_run.id if res.latest_extract_run is not None else None
        ),
        latest_extractor_version=(
            res.latest_extract_run.extractor_version
            if res.latest_extract_run is not None
            else None
        ),
        evidence_references=evidences_out,
        administrative_only=True,
        clinical_approval=False,
    )
