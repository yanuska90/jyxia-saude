"""RBAC-protected and tenant-isolated processing queue consultation and reprocessing routes."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Response
from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_db_session,
    get_settings,
    require_csrf_protection,
    require_org_permission,
)
from app.core.config import Settings
from app.core.constants import IDEMPOTENCY_KEY_HEADER_NAME
from app.core.rbac import RbacPermission
from app.models.entities import (
    ConsistencyAssessment,
    ConsistencyAxisResult,
    Document,
    DocumentVersion,
    EvidenceReference,
    ExtractedField,
    HumanReview,
    ProcessingRun,
    User,
)
from app.schemas.auth import (
    CaseHumanReviewsResponse,
    CaseProcessingRunsListResponse,
    ConsistencyAssessmentDetailResponse,
    ConsistencyAssessmentsListResponse,
    ConsistencyAssessmentSummaryResponse,
    ConsistencyAxisResultResponse,
    CreateHumanReviewRequest,
    DocumentVersionHumanReviewsResponse,
    EvidenceReferencesListResponse,
    EvidenceReferenceSummaryResponse,
    ExtractedFieldItemResponse,
    ExtractedFieldsListResponse,
    HumanReviewResponse,
    ProcessingRunSummaryResponse,
)
from app.schemas.tenant import TenantContext, validate_safe_metadata_text
from app.services.auth_service import AuthorizedMembershipContext
from app.services.institutional_service import (
    DocumentNotFoundError,
    HumanReviewStateConflictError,
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


def _to_assessment_summary(
    assessment: ConsistencyAssessment,
    *,
    axis_statuses: dict[str, str],
) -> ConsistencyAssessmentSummaryResponse:
    return ConsistencyAssessmentSummaryResponse(
        assessment_id=assessment.id,
        organization_id=assessment.organization_id,
        case_id=assessment.case_id,
        processing_run_id=assessment.processing_run_id,
        assessment_sequence=assessment.assessment_sequence,
        engine_name=assessment.engine_name,
        engine_version=assessment.engine_version,
        policy_version=assessment.policy_version,
        input_fingerprint_sha256=assessment.input_fingerprint_sha256,
        automated_axes_outcome=assessment.automated_axes_outcome,
        readiness_state=assessment.readiness_state,
        human_review_completed=assessment.human_review_completed,
        human_review_required=assessment.human_review_required,
        compared_documents_count=assessment.compared_documents_count,
        axis_statuses=axis_statuses,
        limitations=list(assessment.limitations_json or []),
        assessed_at=assessment.assessed_at,
        administrative_only=True,
        clinical_approval=False,
    )


def _to_axis_response(axis_row: ConsistencyAxisResult) -> ConsistencyAxisResultResponse:
    return ConsistencyAxisResultResponse(
        axis_result_id=axis_row.id,
        axis=axis_row.axis_name,
        status=axis_row.status,
        rule=axis_row.rule_code,
        justification=axis_row.justification,
        fields_used=list(axis_row.fields_used_json or []),
        compared_document_ids=list(axis_row.compared_document_ids_json or []),
        compared_version_ids=list(axis_row.compared_version_ids_json or []),
        evidence_reference_ids=list(axis_row.evidence_reference_ids_json or []),
        comparison=list(axis_row.comparison_items_json or []),
        limitations=list(axis_row.limitations_json or []),
        engine_version=axis_row.engine_version,
        administrative_only=True,
        clinical_approval=False,
    )


@router.post(
    "/{organization_id}/cases/{case_id}/consistency-assessments",
    response_model=ProcessingRunSummaryResponse,
    status_code=201,
)
def enqueue_case_consistency_assessment(
    organization_id: str,
    case_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.CASE_WRITE)),
    ],
    _csrf: Annotated[None, Depends(require_csrf_protection)],
    idempotency_key: Annotated[
        str | None, Header(alias=IDEMPOTENCY_KEY_HEADER_NAME)
    ] = None,
) -> ProcessingRunSummaryResponse:
    """Enqueue async compare_consistency worker evaluation without running engine inside HTTP."""
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
        detail = InstitutionalService.enqueue_case_consistency_comparison(
            session,
            ctx,
            case_id=case_id,
            engine_version=settings.consistency_engine_version,
            policy_version=settings.consistency_policy_version,
            idempotency_key=idempotency_key,
            max_attempts=settings.worker_max_attempts,
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


@router.get(
    "/{organization_id}/cases/{case_id}/consistency-assessments",
    response_model=ConsistencyAssessmentsListResponse,
)
def list_case_consistency_assessments(
    organization_id: str,
    case_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> ConsistencyAssessmentsListResponse:
    """List paginated consistency assessments history for a tenant DocumentCase."""
    _ = organization_id
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        page = InstitutionalService.list_case_consistency_assessments(
            session,
            ctx,
            case_id=case_id,
            limit=limit,
            offset=offset,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return ConsistencyAssessmentsListResponse(
        organization_id=ctx.organization_id,
        case_id=page.case.id,
        total=page.total,
        limit=page.limit,
        offset=page.offset,
        assessments=[
            _to_assessment_summary(assess, axis_statuses=ax_map)
            for assess, ax_map in page.items
        ],
        administrative_only=True,
        clinical_approval=False,
    )


@router.get(
    "/{organization_id}/cases/{case_id}/consistency-assessments/{assessment_id}",
    response_model=ConsistencyAssessmentDetailResponse,
)
def get_case_consistency_assessment_detail(
    organization_id: str,
    case_id: str,
    assessment_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
) -> ConsistencyAssessmentDetailResponse:
    """Return full 4-axis breakdown, spatial evidences, limitations, and automated vs review states."""
    _ = organization_id
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        res = InstitutionalService.get_case_consistency_assessment(
            session,
            ctx,
            case_id=case_id,
            assessment_id=assessment_id,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return ConsistencyAssessmentDetailResponse(
        assessment_id=res.assessment.id,
        organization_id=res.assessment.organization_id,
        case_id=res.case.id,
        processing_run_id=res.assessment.processing_run_id,
        assessment_sequence=res.assessment.assessment_sequence,
        engine_name=res.assessment.engine_name,
        engine_version=res.assessment.engine_version,
        policy_version=res.assessment.policy_version,
        input_fingerprint_sha256=res.assessment.input_fingerprint_sha256,
        automated_axes_outcome=res.assessment.automated_axes_outcome,
        readiness_state=res.assessment.readiness_state,
        human_review_completed=res.assessment.human_review_completed,
        human_review_required=res.assessment.human_review_required,
        compared_documents_count=res.assessment.compared_documents_count,
        compared_snapshot=list(res.assessment.compared_snapshot_json or []),
        extraction_run_ids=list(res.assessment.extraction_run_ids_json or []),
        axes=[_to_axis_response(ax) for ax in res.axes],
        limitations=list(res.assessment.limitations_json or []),
        summary=dict(res.assessment.summary_json or {}),
        assessed_at=res.assessment.assessed_at,
        administrative_only=True,
        clinical_approval=False,
    )


def _to_human_review_response(
    review: HumanReview,
    doc: Document,
    ver: DocumentVersion,
    reviewer_user: User | None,
    reviewer_role: str | None,
    *,
    idempotent_replay: bool = False,
    comparison_run: ProcessingRun | None = None,
) -> HumanReviewResponse:
    return HumanReviewResponse(
        review_id=review.id,
        organization_id=review.organization_id,
        case_id=doc.case_id,
        document_id=doc.id,
        document_version_id=ver.id,
        version_number=ver.version_number,
        reviewer_user_id=review.reviewer_user_id,
        reviewer_display_name=reviewer_user.display_name if reviewer_user is not None else None,
        reviewer_email=reviewer_user.email if reviewer_user is not None else None,
        reviewer_role=reviewer_role,
        action_type=review.action_type,
        field_key=review.field_key,
        original_value=review.original_value,
        revised_value=review.revised_value,
        justification=review.justification,
        evidence_reference_id=review.evidence_reference_id,
        policy_version=review.policy_version,
        created_at=review.created_at,
        idempotent_replay=idempotent_replay,
        comparison_processing_run=(
            to_processing_run_summary(
                comparison_run,
                document_id=doc.id,
                case_id=doc.case_id,
            )
            if comparison_run is not None
            else None
        ),
        administrative_only=True,
        clinical_approval=False,
    )


@router.get(
    "/{organization_id}/cases/{case_id}/human-reviews",
    response_model=CaseHumanReviewsResponse,
)
def list_case_human_reviews(
    organization_id: str,
    case_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
) -> CaseHumanReviewsResponse:
    """List append-only administrative human reviews across a tenant DocumentCase."""
    _ = organization_id
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        res = InstitutionalService.list_case_human_reviews(
            session, ctx, case_id=case_id
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return CaseHumanReviewsResponse(
        organization_id=ctx.organization_id,
        case_id=res.case.id,
        active_document_versions_count=res.active_document_versions_count,
        reviewed_active_versions_count=res.reviewed_active_versions_count,
        human_review_completed=res.human_review_completed,
        total=len(res.items),
        reviews=[
            _to_human_review_response(rev, doc, ver, usr, rl)
            for rev, doc, ver, usr, rl in res.items
        ],
        administrative_only=True,
        clinical_approval=False,
    )


@router.get(
    "/{organization_id}/documents/{document_id}/versions/{version_id}/human-reviews",
    response_model=DocumentVersionHumanReviewsResponse,
)
def list_document_version_human_reviews(
    organization_id: str,
    document_id: str,
    version_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
) -> DocumentVersionHumanReviewsResponse:
    """List append-only administrative human reviews for a specific document version."""
    _ = organization_id
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        res = InstitutionalService.list_document_version_human_reviews(
            session, ctx, document_id=document_id, version_id=version_id
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return DocumentVersionHumanReviewsResponse(
        organization_id=ctx.organization_id,
        case_id=res.document.case_id,
        document_id=res.document.id,
        document_version_id=res.version.id,
        version_number=res.version.version_number,
        is_current=res.version.is_current,
        total=len(res.items),
        reviews=[
            _to_human_review_response(rev, doc, ver, usr, rl)
            for rev, doc, ver, usr, rl in res.items
        ],
        administrative_only=True,
        clinical_approval=False,
    )


@router.post(
    "/{organization_id}/documents/{document_id}/versions/{version_id}/human-reviews",
    response_model=HumanReviewResponse,
)
def record_document_version_human_review(
    organization_id: str,
    document_id: str,
    version_id: str,
    payload: CreateHumanReviewRequest,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    settings: Annotated[Settings, Depends(get_settings)],
    _csrf: Annotated[object, Depends(require_csrf_protection)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.FIELD_REVIEW)),
    ],
) -> HumanReviewResponse:
    """Record an append-only administrative human review on an active DocumentVersion."""
    _ = organization_id
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        res = InstitutionalService.record_document_version_human_review(
            session,
            ctx,
            document_id=document_id,
            version_id=version_id,
            action_type=payload.action_type,
            justification=payload.justification,
            field_key=payload.field_key,
            original_value=payload.original_value,
            revised_value=payload.revised_value,
            evidence_reference_id=payload.evidence_reference_id,
            policy_version=payload.policy_version,
            enqueue_comparison=payload.enqueue_comparison,
            engine_version=settings.consistency_engine_version,
            max_attempts=settings.worker_max_attempts,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except HumanReviewStateConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    response.status_code = 200 if res.idempotent_replay else 201
    return _to_human_review_response(
        res.review,
        res.document,
        res.version,
        res.reviewer_user,
        res.reviewer_role,
        idempotent_replay=res.idempotent_replay,
        comparison_run=res.comparison_processing_run,
    )
