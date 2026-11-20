"""Relational models for JYXIA institutional multi-tenant foundation.

Structural multi-tenant isolation is enforced via explicit organization_id columns
and multi-column composite foreign keys so cross-tenant and cross-document/version
linkage is blocked at both repository and database levels.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.constants import (
    CaseReadinessState,
    DocumentKind,
    ExtractedFieldStatus,
    HumanReviewAction,
    MembershipStatus,
    OrganizationRole,
    OrganizationStatus,
    ProcessingStatus,
    StorageDriver,
)
from app.db.base import JSON_VARIANT, Base, new_uuid, utc_now

AUDIT_SCHEMA_VERSION = "jyxia.audit.v1"


def _enum_values_sql(enum_cls: type[StrEnum]) -> str:
    return ", ".join(f"'{member.value}'" for member in enum_cls)


class Organization(Base):
    __tablename__ = "organizations"
    __table_args__ = (
        CheckConstraint(
            f"status IN ({_enum_values_sql(OrganizationStatus)})",
            name="status_valid",
        ),
        CheckConstraint("length(trim(slug)) >= 2", name="slug_min_len"),
        CheckConstraint("length(trim(name)) >= 2", name="name_min_len"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    slug: Mapped[str] = mapped_column(String(80), nullable=False, unique=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=OrganizationStatus.ACTIVE.value
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    # Preserve ON DELETE RESTRICT semantics in ORM instead of cascading deletion.
    memberships: Mapped[list[OrganizationMembership]] = relationship(
        back_populates="organization", passive_deletes="all"
    )
    cases: Mapped[list[DocumentCase]] = relationship(
        back_populates="organization", passive_deletes="all"
    )


class User(Base):
    __tablename__ = "users"
    __table_args__ = (
        CheckConstraint("email = lower(email)", name="email_lowercase"),
        CheckConstraint("length(trim(display_name)) >= 1", name="display_name_nonempty"),
        CheckConstraint(
            "external_subject IS NULL OR length(trim(external_subject)) >= 1",
            name="external_subject_nonempty",
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    external_subject: Mapped[str | None] = mapped_column(String(255), nullable=True, unique=True)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    display_name: Mapped[str] = mapped_column(String(200), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    mfa_enrolled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    memberships: Mapped[list[OrganizationMembership]] = relationship(
        back_populates="user", passive_deletes="all"
    )


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_org_membership_org_user"),
        UniqueConstraint("organization_id", "user_id", "id", name="uq_org_membership_scoped"),
        CheckConstraint(
            f"role IN ({_enum_values_sql(OrganizationRole)})",
            name="role_valid",
        ),
        CheckConstraint(
            f"status IN ({_enum_values_sql(MembershipStatus)})",
            name="status_valid",
        ),
        Index("ix_org_memberships_org_role", "organization_id", "role"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    role: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=MembershipStatus.ACTIVE.value
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")


class DocumentCase(Base):
    __tablename__ = "document_cases"
    __table_args__ = (
        UniqueConstraint("organization_id", "case_code", name="uq_document_cases_org_code"),
        UniqueConstraint("organization_id", "id", name="uq_document_cases_org_id"),
        ForeignKeyConstraint(
            ["organization_id", "created_by_user_id"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            name="fk_document_cases_org_creator",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            f"readiness_state IN ({_enum_values_sql(CaseReadinessState)})",
            name="readiness_state_valid",
        ),
        CheckConstraint("administrative_only = TRUE", name="administrative_only_true"),
        CheckConstraint("clinical_approval = FALSE", name="clinical_approval_false"),
        CheckConstraint("length(trim(case_code)) >= 2", name="case_code_min_len"),
        CheckConstraint(
            "external_reference IS NULL OR length(trim(external_reference)) >= 2",
            name="external_ref_min_len",
        ),
        Index("ix_document_cases_org_state", "organization_id", "readiness_state"),
        Index(
            "uq_document_cases_org_ext_ref",
            "organization_id",
            "external_reference",
            unique=True,
            sqlite_where=text("external_reference IS NOT NULL"),
            postgresql_where=text("external_reference IS NOT NULL"),
        ),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    case_code: Mapped[str] = mapped_column(String(100), nullable=False)
    external_reference: Mapped[str | None] = mapped_column(String(128), nullable=True)
    procedure_reference: Mapped[str | None] = mapped_column(String(200), nullable=True)
    declared_laterality: Mapped[str | None] = mapped_column(String(32), nullable=True)
    readiness_state: Mapped[str] = mapped_column(
        String(64), nullable=False, default=CaseReadinessState.PENDENTE.value
    )
    administrative_only: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    clinical_approval: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_by_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    organization: Mapped[Organization] = relationship(back_populates="cases")
    documents: Mapped[list[Document]] = relationship(back_populates="case", overlaps="case")


class Document(Base):
    __tablename__ = "documents"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_documents_org_id"),
        ForeignKeyConstraint(
            ["organization_id", "case_id"],
            ["document_cases.organization_id", "document_cases.id"],
            name="fk_documents_org_case",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            f"document_kind IN ({_enum_values_sql(DocumentKind)})",
            name="document_kind_valid",
        ),
        CheckConstraint("length(trim(source_label)) >= 1", name="source_label_nonempty"),
        CheckConstraint(
            "discarded_at IS NULL OR (discard_reason IS NOT NULL AND length(trim(discard_reason)) >= 3)",
            name="discard_requires_reason",
        ),
        Index("ix_documents_org_case", "organization_id", "case_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    case_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    document_kind: Mapped[str] = mapped_column(
        String(40), nullable=False, default=DocumentKind.DESCONHECIDO.value
    )
    document_subfamily: Mapped[str | None] = mapped_column(String(80), nullable=True)
    source_label: Mapped[str] = mapped_column(String(160), nullable=False)
    quarantined: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    quarantine_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    discarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    discard_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )

    case: Mapped[DocumentCase | None] = relationship(
        back_populates="documents",
        foreign_keys=[organization_id, case_id],
        primaryjoin=(
            "and_(Document.organization_id == DocumentCase.organization_id, "
            "Document.case_id == DocumentCase.id)"
        ),
    )
    versions: Mapped[list[DocumentVersion]] = relationship(
        back_populates="document",
        foreign_keys="[DocumentVersion.organization_id, DocumentVersion.document_id]",
        primaryjoin=(
            "and_(Document.organization_id == DocumentVersion.organization_id, "
            "Document.id == DocumentVersion.document_id)"
        ),
    )


class DocumentVersion(Base):
    __tablename__ = "document_versions"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_document_versions_org_id"),
        UniqueConstraint(
            "organization_id", "document_id", "id", name="uq_doc_versions_org_doc_id"
        ),
        UniqueConstraint(
            "organization_id", "document_id", "version_number", name="uq_doc_versions_num"
        ),
        ForeignKeyConstraint(
            ["organization_id", "document_id"],
            ["documents.organization_id", "documents.id"],
            name="fk_doc_versions_org_doc",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "document_id", "superseded_by_version_id"],
            [
                "document_versions.organization_id",
                "document_versions.document_id",
                "document_versions.id",
            ],
            name="fk_doc_versions_org_doc_supersede",
            ondelete="RESTRICT",
        ),
        CheckConstraint("version_number >= 1", name="version_number_positive"),
        CheckConstraint(
            "length(trim(sha256_hex)) = 64 AND sha256_hex = lower(sha256_hex)",
            name="sha256_hex_len_64",
        ),
        CheckConstraint("mime_type IN ('application/pdf', 'image/png')", name="mime_type_valid"),
        CheckConstraint("byte_size > 0", name="byte_size_positive"),
        CheckConstraint("page_count IS NULL OR page_count >= 1", name="page_count_positive"),
        CheckConstraint(
            f"storage_driver IN ({_enum_values_sql(StorageDriver)})",
            name="storage_driver_valid",
        ),
        CheckConstraint("length(trim(storage_key)) >= 8", name="storage_key_min_len"),
        CheckConstraint(
            "original_filename IS NULL OR "
            "(length(trim(original_filename)) >= 1 "
            "AND replace(original_filename, '/', '') = original_filename "
            "AND replace(original_filename, '\\', '') = original_filename "
            "AND replace(original_filename, '..', '') = original_filename)",
            name="original_filename_safe",
        ),
        CheckConstraint(
            "superseded_by_version_id IS NULL OR superseded_by_version_id <> id",
            name="no_self_supersede",
        ),
        Index("ix_doc_versions_org_sha256", "organization_id", "sha256_hex"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    document_id: Mapped[str] = mapped_column(String(36), nullable=False)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    sha256_hex: Mapped[str] = mapped_column(String(64), nullable=False)
    mime_type: Mapped[str] = mapped_column(String(64), nullable=False)
    byte_size: Mapped[int] = mapped_column(Integer, nullable=False)
    page_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    original_filename: Mapped[str | None] = mapped_column(String(255), nullable=True)
    storage_driver: Mapped[str] = mapped_column(
        String(64), nullable=False, default=StorageDriver.LOCAL_CONTROLLED_SYNTHETIC.value
    )
    storage_key: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    superseded_by_version_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )

    document: Mapped[Document] = relationship(
        back_populates="versions",
        foreign_keys=[organization_id, document_id],
        primaryjoin=(
            "and_(Document.organization_id == DocumentVersion.organization_id, "
            "Document.id == DocumentVersion.document_id)"
        ),
    )


class ProcessingRun(Base):
    __tablename__ = "processing_runs"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_processing_runs_org_id"),
        UniqueConstraint(
            "organization_id", "document_version_id", "id", name="uq_processing_runs_org_ver_id"
        ),
        UniqueConstraint(
            "organization_id", "idempotency_key", name="uq_processing_runs_org_idemp"
        ),
        ForeignKeyConstraint(
            ["organization_id", "document_version_id"],
            ["document_versions.organization_id", "document_versions.id"],
            name="fk_processing_runs_org_docver",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            f"status IN ({_enum_values_sql(ProcessingStatus)})",
            name="status_valid",
        ),
        CheckConstraint(
            "finished_at IS NULL OR finished_at >= started_at",
            name="finished_after_started",
        ),
        Index("ix_processing_runs_org_docver", "organization_id", "document_version_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    document_version_id: Mapped[str] = mapped_column(String(36), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    extractor_version: Mapped[str] = mapped_column(String(64), nullable=False)
    idempotency_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    status: Mapped[str] = mapped_column(
        String(32), nullable=False, default=ProcessingStatus.PENDING.value
    )
    readable: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    readiness_state: Mapped[str | None] = mapped_column(String(64), nullable=True)
    axes_summary: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT, nullable=True)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class ExtractedField(Base):
    __tablename__ = "extracted_fields"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_extracted_fields_org_id"),
        UniqueConstraint(
            "organization_id",
            "document_version_id",
            "id",
            name="uq_extracted_fields_org_ver_id",
        ),
        ForeignKeyConstraint(
            ["organization_id", "document_version_id", "processing_run_id"],
            [
                "processing_runs.organization_id",
                "processing_runs.document_version_id",
                "processing_runs.id",
            ],
            name="fk_extracted_fields_org_ver_run",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "document_version_id"],
            ["document_versions.organization_id", "document_versions.id"],
            name="fk_extracted_fields_org_docver",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            f"status IN ({_enum_values_sql(ExtractedFieldStatus)})",
            name="status_valid",
        ),
        CheckConstraint("length(trim(field_key)) >= 1", name="field_key_nonempty"),
        CheckConstraint(
            "(status <> 'abstained') OR (abstained = TRUE)",
            name="abstained_status_coherent",
        ),
        Index("ix_extracted_fields_org_run", "organization_id", "processing_run_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    processing_run_id: Mapped[str] = mapped_column(String(36), nullable=False)
    document_version_id: Mapped[str] = mapped_column(String(36), nullable=False)
    field_key: Mapped[str] = mapped_column(String(64), nullable=False)
    raw_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    normalized_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    abstained: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    metadata_json: Mapped[dict[str, Any] | None] = mapped_column(JSON_VARIANT, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class EvidenceReference(Base):
    """Normalized [x, y, w, h] coordinates in top-left page-relative space [0.0, 1.0]."""

    __tablename__ = "evidence_references"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_evidence_refs_org_id"),
        UniqueConstraint(
            "organization_id", "document_version_id", "id", name="uq_evidence_refs_org_ver_id"
        ),
        ForeignKeyConstraint(
            ["organization_id", "document_version_id", "extracted_field_id"],
            [
                "extracted_fields.organization_id",
                "extracted_fields.document_version_id",
                "extracted_fields.id",
            ],
            name="fk_evidence_refs_org_ver_field",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "document_version_id"],
            ["document_versions.organization_id", "document_versions.id"],
            name="fk_evidence_refs_org_docver",
            ondelete="RESTRICT",
        ),
        CheckConstraint("page_number >= 1", name="page_number_positive"),
        CheckConstraint("bbox_x >= 0.0 AND bbox_x <= 1.0", name="bbox_x_bounds"),
        CheckConstraint("bbox_y >= 0.0 AND bbox_y <= 1.0", name="bbox_y_bounds"),
        CheckConstraint("bbox_w > 0.0 AND bbox_w <= 1.0", name="bbox_w_bounds"),
        CheckConstraint("bbox_h > 0.0 AND bbox_h <= 1.0", name="bbox_h_bounds"),
        CheckConstraint("bbox_x + bbox_w <= 1.00001", name="bbox_x_w_within_page"),
        CheckConstraint("bbox_y + bbox_h <= 1.00001", name="bbox_y_h_within_page"),
        Index("ix_evidence_refs_org_field", "organization_id", "extracted_field_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    extracted_field_id: Mapped[str] = mapped_column(String(36), nullable=False)
    document_version_id: Mapped[str] = mapped_column(String(36), nullable=False)
    page_number: Mapped[int] = mapped_column(Integer, nullable=False)
    bbox_x: Mapped[float] = mapped_column(Float, nullable=False)
    bbox_y: Mapped[float] = mapped_column(Float, nullable=False)
    bbox_w: Mapped[float] = mapped_column(Float, nullable=False)
    bbox_h: Mapped[float] = mapped_column(Float, nullable=False)
    quote_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    extraction_method: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class HumanReview(Base):
    __tablename__ = "human_reviews"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "document_version_id"],
            ["document_versions.organization_id", "document_versions.id"],
            name="fk_human_reviews_org_docver",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "document_version_id", "evidence_reference_id"],
            [
                "evidence_references.organization_id",
                "evidence_references.document_version_id",
                "evidence_references.id",
            ],
            name="fk_human_reviews_org_ver_evidence",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "reviewer_user_id"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            name="fk_human_reviews_org_reviewer",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            f"action_type IN ({_enum_values_sql(HumanReviewAction)})",
            name="action_type_valid",
        ),
        CheckConstraint("length(trim(justification)) >= 5", name="justification_min_len"),
        Index("ix_human_reviews_org_docver", "organization_id", "document_version_id"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    document_version_id: Mapped[str] = mapped_column(String(36), nullable=False)
    reviewer_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    action_type: Mapped[str] = mapped_column(String(64), nullable=False)
    field_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    original_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    revised_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    justification: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_reference_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    policy_version: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


class AuditEvent(Base):
    """Organization-scoped append-only hash-chained ledger.

    Database triggers (migration 0002) reject direct SQL UPDATE/DELETE operations by normal
    database clients; note that privileged DB administrators remain outside application threat guarantees.
    """

    __tablename__ = "audit_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "sequence_number", name="uq_audit_events_org_seq"),
        UniqueConstraint("organization_id", "event_hash", name="uq_audit_events_org_hash"),
        ForeignKeyConstraint(
            ["organization_id", "actor_user_id"],
            ["organization_memberships.organization_id", "organization_memberships.user_id"],
            name="fk_audit_events_org_actor",
            ondelete="RESTRICT",
        ),
        CheckConstraint("sequence_number >= 1", name="sequence_number_positive"),
        CheckConstraint(
            "length(trim(prev_event_hash)) = 64 AND prev_event_hash = lower(prev_event_hash)",
            name="prev_hash_len_64",
        ),
        CheckConstraint(
            "length(trim(event_hash)) = 64 AND event_hash = lower(event_hash)",
            name="event_hash_len_64",
        ),
        CheckConstraint("length(trim(schema_version)) >= 3", name="schema_version_nonempty"),
        CheckConstraint("length(trim(event_type)) >= 2", name="event_type_min_len"),
        CheckConstraint("length(trim(target_entity_type)) >= 2", name="target_entity_min_len"),
        Index("ix_audit_events_org_created", "organization_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    organization_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=False
    )
    schema_version: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default=AUDIT_SCHEMA_VERSION,
        server_default=text(f"'{AUDIT_SCHEMA_VERSION}'"),
    )
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    actor_user_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("users.id", ondelete="RESTRICT"), nullable=True
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_entity_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_entity_id: Mapped[str] = mapped_column(String(36), nullable=False)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON_VARIANT, nullable=False)
    prev_event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )


@event.listens_for(AuditEvent, "before_update")
def _forbid_audit_update(_mapper: Any, _connection: Any, _target: AuditEvent) -> None:
    raise ValueError("AuditEvent is strictly append-only and cannot be modified.")


@event.listens_for(AuditEvent, "before_delete")
def _forbid_audit_delete(_mapper: Any, _connection: Any, _target: AuditEvent) -> None:
    raise ValueError("AuditEvent is strictly append-only and cannot be deleted.")
