"""RBAC-protected and tenant-isolated institutional organization and document ingestion endpoints."""

from __future__ import annotations

import re
from typing import Annotated

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, Response
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.api.dependencies import (
    get_db_session,
    get_document_storage,
    require_csrf_protection,
    require_org_permission,
)
from app.api.routes.processing import to_processing_run_summary
from app.core.constants import (
     DocumentKind,
    IDEMPOTENCY_KEY_HEADER_NAME,
    OrganizationRole,
)
from app.core.multipart import MultipartUploadError, parse_multipart_document_upload
from app.core.rbac import (
    AuthenticatedSessionPrincipal,
    RbacPermission,
    permissions_for_role,
)
from app.models.entities import Document, DocumentVersion
from app.repositories.identity import SecurityAuditRepository
from app.repositories.institutional import (
    AuditEventRepository,
    CaseAndDocumentRepository,
    OrganizationRepository,
)
from app.schemas.auth import (
    AccessContextResponse,
    AuditEventSummaryResponse,
    CaseDocumentsListResponse,
    CaseSummaryResponse,
    DocumentDetailResponse,
    DocumentIngestionResponse,
    DocumentSummaryResponse,
    DocumentVersionSummaryResponse,
    MemberSummaryResponse,
    OrganizationAuditEventsResponse,
    OrganizationCasesResponse,
    OrganizationMembersResponse,
    SecurityAuditEventSummaryResponse,
)
from app.schemas.tenant import TenantContext, validate_safe_metadata_text
from app.services.auth_service import AuthorizedMembershipContext
from app.services.institutional_service import (
    DocumentNotFoundError,
    IdempotencyConflictError,
    InstitutionalService,
)
from app.services.storage import (
    DocumentStoragePort,
    StorageIntegrityError,
    StorageObjectNotFoundError,
    StoragePayloadTooLargeError,
    StorageUnavailableError,
    StorageUnsupportedFormatError,
    StorageValidationError,
)

router = APIRouter(prefix="/organizations", tags=["organizations"])

_NO_STORE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
    "X-Content-Type-Options": "nosniff",
}
_SAFE_DISPOSITION_CHARS_RE = re.compile(r"[^A-Za-z0-9._\-]")


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


def _to_version_summary(ver: DocumentVersion) -> DocumentVersionSummaryResponse:
    return DocumentVersionSummaryResponse(
        version_id=ver.id,
        document_id=ver.document_id,
        organization_id=ver.organization_id,
        version_number=ver.version_number,
        sha256_hex=ver.sha256_hex,
        mime_type=ver.mime_type,
        byte_size=ver.byte_size,
        page_count=ver.page_count,
        original_filename=ver.original_filename,
        created_by_user_id=ver.created_by_user_id,
        is_current=ver.is_current,
        created_at=ver.created_at,
    )


def _to_document_summary(
    doc: Document, current_version: DocumentVersion | None
) -> DocumentSummaryResponse:
    return DocumentSummaryResponse(
        document_id=doc.id,
        organization_id=doc.organization_id,
        case_id=doc.case_id,
        document_kind=doc.document_kind,
        document_subfamily=doc.document_subfamily,
        source_label=doc.source_label,
        external_reference=doc.external_reference,
        description=doc.description,
        created_by_user_id=doc.created_by_user_id,
        quarantined=doc.quarantined,
        administrative_only=True,
        clinical_approval=False,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        current_version=_to_version_summary(current_version) if current_version else None,
    )


def _sanitize_content_disposition_filename(filename: str, fallback: str) -> str:
    cleaned = _SAFE_DISPOSITION_CHARS_RE.sub("_", filename.strip())
    if not cleaned or cleaned in {".", ".."}:
        return fallback
    return cleaned[:180]


@router.get("/{organization_id}/access-context", response_model=AccessContextResponse)
def get_organization_access_context(
    response: Response,
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.ORGANIZATION_READ)),
    ],
) -> AccessContextResponse:
    """Return server-verified multi-tenant RBAC access context for the caller."""
    _set_no_store(response)
    role = auth_ctx.principal.role
    return AccessContextResponse(
        organization_id=auth_ctx.organization.id,
        organization_slug=auth_ctx.organization.slug,
        organization_name=auth_ctx.organization.name,
        user_id=auth_ctx.principal.user_id,
        role=role,
        permissions=sorted(perm.value for perm in permissions_for_role(role)),
        mfa_verified_at=auth_ctx.principal.session.mfa_verified_at,
        administrative_only=True,
        clinical_approval=False,
    )


@router.get("/{organization_id}/cases", response_model=OrganizationCasesResponse)
def list_organization_cases(
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.CASE_READ)),
    ],
) -> OrganizationCasesResponse:
    """List tenant-scoped administrative cases for an authorized organization member."""
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    cases = CaseAndDocumentRepository.list_cases(session, ctx)
    return OrganizationCasesResponse(
        organization_id=auth_ctx.organization.id,
        role=auth_ctx.principal.role,
        cases=[
            CaseSummaryResponse(
                case_id=c.id,
                organization_id=c.organization_id,
                case_code=c.case_code,
                external_reference=c.external_reference,
                procedure_reference=c.procedure_reference,
                readiness_state=c.readiness_state,
                administrative_only=c.administrative_only,
                clinical_approval=c.clinical_approval,
                created_at=c.created_at,
            )
            for c in cases
        ],
    )


@router.get("/{organization_id}/members", response_model=OrganizationMembersResponse)
def list_organization_members(
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.MEMBERSHIP_READ)),
    ],
) -> OrganizationMembersResponse:
    """List memberships of the active organization (RBAC-restricted to authorized roles)."""
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    rows = OrganizationRepository.list_memberships_with_users(session, ctx)
    return OrganizationMembersResponse(
        organization_id=auth_ctx.organization.id,
        members=[
            MemberSummaryResponse(
                membership_id=m.id,
                user_id=u.id,
                display_name=u.display_name,
                email=u.email,
                role=OrganizationRole(m.role),
                status=m.status,
                created_at=m.created_at,
            )
            for m, u in rows
        ],
    )


@router.get("/{organization_id}/audit-events", response_model=OrganizationAuditEventsResponse)
def list_organization_audit_events(
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.AUDIT_READ)),
    ],
) -> OrganizationAuditEventsResponse:
    """List tenant-scoped immutable audit ledger and org security events (org_admin / auditor)."""
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    audit_rows = AuditEventRepository.list_events(session, ctx)
    sec_rows = SecurityAuditRepository.list_org_events(session, ctx)
    return OrganizationAuditEventsResponse(
        organization_id=auth_ctx.organization.id,
        audit_events=[
            AuditEventSummaryResponse(
                id=ev.id,
                sequence_number=ev.sequence_number,
                event_type=ev.event_type,
                actor_user_id=ev.actor_user_id,
                target_entity_type=ev.target_entity_type,
                target_entity_id=ev.target_entity_id,
                payload_json=ev.payload_json,
                event_hash=ev.event_hash,
                created_at=ev.created_at,
            )
            for ev in audit_rows
        ],
        security_events=[
            SecurityAuditEventSummaryResponse(
                id=ev.id,
                sequence_number=ev.sequence_number,
                event_type=ev.event_type,
                outcome=ev.outcome,
                user_id=ev.user_id,
                organization_id=ev.organization_id,
                reason_code=ev.reason_code,
                event_hash=ev.event_hash,
                created_at=ev.created_at,
            )
            for ev in sec_rows
        ],
    )


@router.post(
    "/{organization_id}/cases/{case_id}/documents",
    response_model=DocumentIngestionResponse,
    status_code=201,
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "multipart/form-data": {
                    "schema": {
                        "type": "object",
                        "required": ["file"],
                        "properties": {
                            "file": {"type": "string", "format": "binary"},
                            "document_kind": {
                                "type": "string",
                                "enum": [k.value for k in DocumentKind],
                            },
                            "document_subfamily": {"type": "string"},
                            "source_label": {"type": "string"},
                            "external_reference": {"type": "string"},
                            "description": {"type": "string"},
                            "original_filename": {"type": "string"},
                        },
                    }
                }
            },
        }
    },
)
async def upload_case_document(
    organization_id: str,
    case_id: str,
    request: Request,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    _csrf_principal: Annotated[
        AuthenticatedSessionPrincipal, Depends(require_csrf_protection)
    ],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_UPLOAD)),
    ],
    storage: Annotated[DocumentStoragePort, Depends(get_document_storage)],
    idempotency_key_header: Annotated[
        str | None, Header(alias=IDEMPOTENCY_KEY_HEADER_NAME)
    ] = None,
) -> DocumentIngestionResponse:
    """Ingest a validated synthetic PDF/PNG document into an organization's document case."""
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)

    # Verify target case belongs to the active organization before reading/storing any file stream
    case = CaseAndDocumentRepository.get_case(session, ctx, case_id)
    if case is None:
        raise HTTPException(
            status_code=404,
            detail="Document case was not found inside the active organization.",
        )

    cleaned_idemp_key: str | None = None
    if idempotency_key_header is not None and idempotency_key_header.strip():
        try:
            cleaned_idemp_key = validate_safe_metadata_text(
                idempotency_key_header,
                field_name="Idempotency-Key",
                min_len=4,
                max_len=128,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    try:
        parsed = await parse_multipart_document_upload(
            content_type=request.headers.get("content-type"),
            body_stream=request.stream(),
            storage=storage,
            organization_id=ctx.organization_id,
        )
    except StoragePayloadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except StorageUnsupportedFormatError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except StorageUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (MultipartUploadError, StorageValidationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    stored_obj = parsed.stored_object
    fields = parsed.fields

    raw_kind = fields.get("document_kind", DocumentKind.DESCONHECIDO.value).strip().lower()
    if not raw_kind:
        raw_kind = DocumentKind.DESCONHECIDO.value
    try:
        doc_kind = DocumentKind(raw_kind)
    except ValueError as exc:
        storage.delete_uncommitted_object(
            organization_id=ctx.organization_id,
            storage_key=stored_obj.storage_key,
        )
        raise HTTPException(
            status_code=422,
            detail=f"Invalid document_kind '{raw_kind}'.",
        ) from exc

    raw_source = fields.get("source_label")
    effective_source = (
        raw_source.strip()
        if raw_source is not None and raw_source.strip()
        else "institutional_upload"
    )
    if raw_source is not None and (
        "\x00" in raw_source or any(ord(ch) < 32 or ord(ch) == 127 for ch in raw_source)
    ):
        storage.delete_uncommitted_object(
            organization_id=ctx.organization_id,
            storage_key=stored_obj.storage_key,
        )
        raise HTTPException(status_code=422, detail="Invalid control character in source_label.")

    try:
        ingestion = InstitutionalService.ingest_case_document(
            session,
            ctx,
            storage=storage,
            case_id=case.id,
            stored_object=stored_obj,
            document_kind=doc_kind,
            document_subfamily=fields.get("document_subfamily"),
            source_label=effective_source,
            external_reference=fields.get("external_reference"),
            description=fields.get("description"),
            idempotency_key=cleaned_idemp_key,
        )
    except IdempotencyConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except StoragePayloadTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except StorageUnsupportedFormatError as exc:
        raise HTTPException(status_code=415, detail=str(exc)) from exc
    except StorageUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (ValidationError, ValueError, StorageValidationError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    if ingestion.idempotent_replay:
        response.status_code = 200
    else:
        response.status_code = 201

    doc = ingestion.document
    ver = ingestion.version
    assert doc.case_id is not None
    initial_run = (
        to_processing_run_summary(
            ingestion.initial_processing_run,
            document_id=doc.id,
            case_id=doc.case_id,
        )
        if ingestion.initial_processing_run is not None
        else None
    )
    return DocumentIngestionResponse(
        document_id=doc.id,
        organization_id=doc.organization_id,
        case_id=doc.case_id,
        document_kind=doc.document_kind,
        document_subfamily=doc.document_subfamily,
        source_label=doc.source_label,
        external_reference=doc.external_reference,
        description=doc.description,
        created_by_user_id=doc.created_by_user_id,
        quarantined=doc.quarantined,
        idempotent_replay=ingestion.idempotent_replay,
        administrative_only=True,
        clinical_approval=False,
        created_at=doc.created_at,
        current_version=_to_version_summary(ver),
        initial_processing_run=initial_run,
    )


@router.get(
    "/{organization_id}/cases/{case_id}/documents",
    response_model=CaseDocumentsListResponse,
)
def list_case_documents(
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
) -> CaseDocumentsListResponse:
    """List documents and their current version metadata for an authorized organization case."""
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        page = InstitutionalService.list_case_documents_with_versions(
            session,
            ctx,
            case_id=case_id,
            limit=limit,
            offset=offset,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    return CaseDocumentsListResponse(
        organization_id=auth_ctx.organization.id,
        case_id=page.case.id,
        total=page.total,
        limit=page.limit,
        offset=page.offset,
        documents=[_to_document_summary(doc, ver) for doc, ver in page.items],
    )


@router.get(
    "/{organization_id}/documents/{document_id}",
    response_model=DocumentDetailResponse,
)
def get_organization_document_metadata(
    organization_id: str,
    document_id: str,
    response: Response,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
) -> DocumentDetailResponse:
    """Return administrative metadata and version list for a tenant-scoped document."""
    _set_no_store(response)
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        detail = InstitutionalService.get_document_with_versions(
            session,
            ctx,
            document_id=document_id,
        )
    except DocumentNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc

    doc = detail.document
    return DocumentDetailResponse(
        document_id=doc.id,
        organization_id=doc.organization_id,
        case_id=doc.case_id,
        document_kind=doc.document_kind,
        document_subfamily=doc.document_subfamily,
        source_label=doc.source_label,
        external_reference=doc.external_reference,
        description=doc.description,
        created_by_user_id=doc.created_by_user_id,
        quarantined=doc.quarantined,
        quarantine_reason=doc.quarantine_reason,
        administrative_only=True,
        clinical_approval=False,
        created_at=doc.created_at,
        updated_at=doc.updated_at,
        current_version=(
            _to_version_summary(detail.current_version)
            if detail.current_version is not None
            else None
        ),
        versions=[_to_version_summary(v) for v in detail.versions],
    )


@router.get("/{organization_id}/documents/{document_id}/versions/{version_id}/content")
def download_document_version_content(
    organization_id: str,
    document_id: str,
    version_id: str,
    session: Annotated[Session, Depends(get_db_session)],
    auth_ctx: Annotated[
        AuthorizedMembershipContext,
        Depends(require_org_permission(RbacPermission.DOCUMENT_READ)),
    ],
    storage: Annotated[DocumentStoragePort, Depends(get_document_storage)],
) -> Response:
    """Retrieve controlled binary content of an authorized document version with SHA-256 verification."""
    ctx = _to_tenant_ctx(auth_ctx)
    try:
        content_result = InstitutionalService.retrieve_document_version_content(
            session,
            ctx,
            storage=storage,
            document_id=document_id,
            version_id=version_id,
        )
    except (DocumentNotFoundError, StorageObjectNotFoundError) as exc:
        raise HTTPException(
            status_code=404,
            detail="Requested document version content was not found inside active organization.",
        ) from exc
    except StorageUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except (StorageIntegrityError, StorageValidationError) as exc:
        raise HTTPException(
            status_code=500,
            detail="Stored document object failed integrity verification.",
        ) from exc

    ext = "pdf" if content_result.version.mime_type == "application/pdf" else "png"
    fallback_name = f"document-{content_result.document.id[:8]}-v{content_result.version.version_number}.{ext}"
    safe_dl_name = _sanitize_content_disposition_filename(
        content_result.download_filename, fallback_name
    )
    headers = {
        **_NO_STORE_HEADERS,
        "Content-Disposition": f'attachment; filename="{safe_dl_name}"',
        "X-Document-SHA256": content_result.version.sha256_hex,
    }
    return Response(
        content=content_result.content,
        media_type=content_result.version.mime_type,
        headers=headers,
    )
