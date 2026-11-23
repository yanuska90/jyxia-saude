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
from app.models.entities import ProcessingRun
from app.schemas.auth import CaseProcessingRunsListResponse, ProcessingRunSummaryResponse
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
