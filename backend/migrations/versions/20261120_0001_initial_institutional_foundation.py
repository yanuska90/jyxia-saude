"""Initial JYXIA institutional multi-tenant foundation schema.

Revision ID: 20261120_0001
Revises:
Create Date: 2026-11-20 12:15:00+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

revision = "20261120_0001"
down_revision = None
branch_labels = None
depends_on = None

JSON_VARIANT = sa.JSON().with_variant(JSONB(), "postgresql")


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("slug", sa.String(length=80), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("status IN ('active', 'suspended')", name="ck_organizations_status_valid"),
        sa.CheckConstraint("length(trim(slug)) >= 2", name="ck_organizations_slug_min_len"),
        sa.CheckConstraint("length(trim(name)) >= 2", name="ck_organizations_name_min_len"),
        sa.PrimaryKeyConstraint("id", name="pk_organizations"),
        sa.UniqueConstraint("slug", name="uq_organizations_slug"),
    )

    op.create_table(
        "users",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("external_subject", sa.String(length=255), nullable=True),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("mfa_enrolled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("email = lower(email)", name="ck_users_email_lowercase"),
        sa.CheckConstraint("length(trim(display_name)) >= 1", name="ck_users_display_name_nonempty"),
        sa.PrimaryKeyConstraint("id", name="pk_users"),
        sa.UniqueConstraint("email", name="uq_users_email"),
        sa.UniqueConstraint("external_subject", name="uq_users_external_subject"),
    )

    op.create_table(
        "organization_memberships",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("role", sa.String(length=40), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "role IN ('org_admin', 'clinical_reviewer', 'admin_operator', 'auditor_readonly')",
            name="ck_organization_memberships_role_valid",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'revoked')",
            name="ck_organization_memberships_status_valid",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_organization_memberships_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name="fk_organization_memberships_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_organization_memberships"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_org_membership_org_user"),
        sa.UniqueConstraint("organization_id", "user_id", "id", name="uq_org_membership_scoped"),
    )
    op.create_index(
        "ix_org_memberships_org_role",
        "organization_memberships",
        ["organization_id", "role"],
        unique=False,
    )

    op.create_table(
        "document_cases",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("case_code", sa.String(length=100), nullable=False),
        sa.Column("procedure_reference", sa.String(length=200), nullable=True),
        sa.Column("declared_laterality", sa.String(length=32), nullable=True),
        sa.Column("readiness_state", sa.String(length=64), nullable=False),
        sa.Column("administrative_only", sa.Boolean(), nullable=False),
        sa.Column("clinical_approval", sa.Boolean(), nullable=False),
        sa.Column("created_by_user_id", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "readiness_state IN ('pendente', 'bloqueado', 'abstencao', 'conferida_com_escopo_limitado', 'conferida')",
            name="ck_document_cases_readiness_state_valid",
        ),
        sa.CheckConstraint("administrative_only = TRUE", name="ck_document_cases_administrative_only_true"),
        sa.CheckConstraint("clinical_approval = FALSE", name="ck_document_cases_clinical_approval_false"),
        sa.CheckConstraint("length(trim(case_code)) >= 2", name="ck_document_cases_case_code_min_len"),
        sa.ForeignKeyConstraint(
            ["created_by_user_id"],
            ["users.id"],
            name="fk_document_cases_created_by_user_id_users",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_document_cases_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_document_cases"),
        sa.UniqueConstraint("organization_id", "case_code", name="uq_document_cases_org_code"),
        sa.UniqueConstraint("organization_id", "id", name="uq_document_cases_org_id"),
    )
    op.create_index(
        "ix_document_cases_org_state",
        "document_cases",
        ["organization_id", "readiness_state"],
        unique=False,
    )

    op.create_table(
        "documents",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("case_id", sa.String(length=36), nullable=True),
        sa.Column("document_kind", sa.String(length=40), nullable=False),
        sa.Column("document_subfamily", sa.String(length=80), nullable=True),
        sa.Column("source_label", sa.String(length=160), nullable=False),
        sa.Column("quarantined", sa.Boolean(), nullable=False),
        sa.Column("quarantine_reason", sa.Text(), nullable=True),
        sa.Column("discarded_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("discard_reason", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "document_kind IN ('laudo', 'pedido', 'termo', 'imagem', 'desconhecido')",
            name="ck_documents_document_kind_valid",
        ),
        sa.CheckConstraint("length(trim(source_label)) >= 1", name="ck_documents_source_label_nonempty"),
        sa.ForeignKeyConstraint(
            ["organization_id", "case_id"],
            ["document_cases.organization_id", "document_cases.id"],
            name="fk_documents_org_case",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_documents_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_documents"),
        sa.UniqueConstraint("organization_id", "id", name="uq_documents_org_id"),
    )
    op.create_index("ix_documents_org_case", "documents", ["organization_id", "case_id"], unique=False)

    op.create_table(
        "document_versions",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("document_id", sa.String(length=36), nullable=False),
        sa.Column("version_number", sa.Integer(), nullable=False),
        sa.Column("sha256_hex", sa.String(length=64), nullable=False),
        sa.Column("mime_type", sa.String(length=64), nullable=False),
        sa.Column("byte_size", sa.Integer(), nullable=False),
        sa.Column("page_count", sa.Integer(), nullable=True),
        sa.Column("storage_driver", sa.String(length=64), nullable=False),
        sa.Column("storage_key", sa.String(length=255), nullable=False),
        sa.Column("superseded_by_version_id", sa.String(length=36), nullable=True),
        sa.Column("is_current", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("version_number >= 1", name="ck_document_versions_version_number_positive"),
        sa.CheckConstraint("length(sha256_hex) = 64", name="ck_document_versions_sha256_hex_len_64"),
        sa.CheckConstraint("mime_type IN ('application/pdf', 'image/png')", name="ck_document_versions_mime_type_valid"),
        sa.CheckConstraint("byte_size > 0", name="ck_document_versions_byte_size_positive"),
        sa.CheckConstraint("page_count IS NULL OR page_count >= 1", name="ck_document_versions_page_count_positive"),
        sa.CheckConstraint("storage_driver IN ('local_controlled_synthetic')", name="ck_document_versions_storage_driver_valid"),
        sa.CheckConstraint(
            "superseded_by_version_id IS NULL OR superseded_by_version_id <> id",
            name="ck_document_versions_no_self_supersede",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "document_id"],
            ["documents.organization_id", "documents.id"],
            name="fk_doc_versions_org_doc",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "superseded_by_version_id"],
            ["document_versions.organization_id", "document_versions.id"],
            name="fk_doc_versions_org_supersede",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_document_versions_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_document_versions"),
        sa.UniqueConstraint("organization_id", "document_id", "version_number", name="uq_doc_versions_num"),
        sa.UniqueConstraint("organization_id", "id", name="uq_document_versions_org_id"),
        sa.UniqueConstraint("storage_key", name="uq_document_versions_storage_key"),
    )
    op.create_index(
        "ix_doc_versions_org_sha256",
        "document_versions",
        ["organization_id", "sha256_hex"],
        unique=False,
    )

    op.create_table(
        "processing_runs",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("document_version_id", sa.String(length=36), nullable=False),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("extractor_version", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("readable", sa.Boolean(), nullable=False),
        sa.Column("readiness_state", sa.String(length=64), nullable=True),
        sa.Column("axes_summary", JSON_VARIANT, nullable=True),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finished_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('pending', 'running', 'completed', 'abstained', 'quarantined', 'failed')",
            name="ck_processing_runs_status_valid",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "document_version_id"],
            ["document_versions.organization_id", "document_versions.id"],
            name="fk_processing_runs_org_docver",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_processing_runs_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_processing_runs"),
        sa.UniqueConstraint("organization_id", "id", name="uq_processing_runs_org_id"),
    )
    op.create_index(
        "ix_processing_runs_org_docver",
        "processing_runs",
        ["organization_id", "document_version_id"],
        unique=False,
    )

    op.create_table(
        "extracted_fields",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("processing_run_id", sa.String(length=36), nullable=False),
        sa.Column("document_version_id", sa.String(length=36), nullable=False),
        sa.Column("field_key", sa.String(length=64), nullable=False),
        sa.Column("raw_value", sa.Text(), nullable=True),
        sa.Column("normalized_value", sa.Text(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("abstained", sa.Boolean(), nullable=False),
        sa.Column("metadata_json", JSON_VARIANT, nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "status IN ('extracted', 'abstained', 'ambiguous', 'unreadable')",
            name="ck_extracted_fields_status_valid",
        ),
        sa.CheckConstraint("length(trim(field_key)) >= 1", name="ck_extracted_fields_field_key_nonempty"),
        sa.ForeignKeyConstraint(
            ["organization_id", "document_version_id"],
            ["document_versions.organization_id", "document_versions.id"],
            name="fk_extracted_fields_org_docver",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "processing_run_id"],
            ["processing_runs.organization_id", "processing_runs.id"],
            name="fk_extracted_fields_org_run",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_extracted_fields_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_extracted_fields"),
        sa.UniqueConstraint("organization_id", "id", name="uq_extracted_fields_org_id"),
    )
    op.create_index(
        "ix_extracted_fields_org_run",
        "extracted_fields",
        ["organization_id", "processing_run_id"],
        unique=False,
    )

    op.create_table(
        "evidence_references",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("extracted_field_id", sa.String(length=36), nullable=False),
        sa.Column("document_version_id", sa.String(length=36), nullable=False),
        sa.Column("page_number", sa.Integer(), nullable=False),
        sa.Column("bbox_x", sa.Float(), nullable=False),
        sa.Column("bbox_y", sa.Float(), nullable=False),
        sa.Column("bbox_w", sa.Float(), nullable=False),
        sa.Column("bbox_h", sa.Float(), nullable=False),
        sa.Column("quote_excerpt", sa.Text(), nullable=True),
        sa.Column("extraction_method", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("page_number >= 1", name="ck_evidence_references_page_number_positive"),
        sa.CheckConstraint("bbox_x >= 0.0 AND bbox_x <= 1.0", name="ck_evidence_references_bbox_x_bounds"),
        sa.CheckConstraint("bbox_y >= 0.0 AND bbox_y <= 1.0", name="ck_evidence_references_bbox_y_bounds"),
        sa.CheckConstraint("bbox_w > 0.0 AND bbox_w <= 1.0", name="ck_evidence_references_bbox_w_bounds"),
        sa.CheckConstraint("bbox_h > 0.0 AND bbox_h <= 1.0", name="ck_evidence_references_bbox_h_bounds"),
        sa.ForeignKeyConstraint(
            ["organization_id", "document_version_id"],
            ["document_versions.organization_id", "document_versions.id"],
            name="fk_evidence_refs_org_docver",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "extracted_field_id"],
            ["extracted_fields.organization_id", "extracted_fields.id"],
            name="fk_evidence_refs_org_field",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_evidence_references_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_evidence_references"),
        sa.UniqueConstraint("organization_id", "id", name="uq_evidence_refs_org_id"),
    )
    op.create_index(
        "ix_evidence_refs_org_field",
        "evidence_references",
        ["organization_id", "extracted_field_id"],
        unique=False,
    )

    op.create_table(
        "human_reviews",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("document_version_id", sa.String(length=36), nullable=False),
        sa.Column("reviewer_user_id", sa.String(length=36), nullable=False),
        sa.Column("action_type", sa.String(length=64), nullable=False),
        sa.Column("field_key", sa.String(length=64), nullable=True),
        sa.Column("original_value", sa.Text(), nullable=True),
        sa.Column("revised_value", sa.Text(), nullable=True),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("evidence_reference_id", sa.String(length=36), nullable=True),
        sa.Column("policy_version", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "action_type IN ('observed', 'not_observed', 'date_correction', 'quarantine_ack', 'case_link_confirmation', 'replacement_confirmation', 'abstention_review')",
            name="ck_human_reviews_action_type_valid",
        ),
        sa.CheckConstraint("length(trim(justification)) >= 5", name="ck_human_reviews_justification_min_len"),
        sa.ForeignKeyConstraint(
            ["organization_id", "document_version_id"],
            ["document_versions.organization_id", "document_versions.id"],
            name="fk_human_reviews_org_docver",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "evidence_reference_id"],
            ["evidence_references.organization_id", "evidence_references.id"],
            name="fk_human_reviews_org_evidence",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_human_reviews_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["reviewer_user_id"],
            ["users.id"],
            name="fk_human_reviews_reviewer_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_human_reviews"),
    )
    op.create_index(
        "ix_human_reviews_org_docver",
        "human_reviews",
        ["organization_id", "document_version_id"],
        unique=False,
    )

    op.create_table(
        "audit_events",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("organization_id", sa.String(length=36), nullable=False),
        sa.Column("sequence_number", sa.Integer(), nullable=False),
        sa.Column("actor_user_id", sa.String(length=36), nullable=True),
        sa.Column("event_type", sa.String(length=64), nullable=False),
        sa.Column("target_entity_type", sa.String(length=64), nullable=False),
        sa.Column("target_entity_id", sa.String(length=36), nullable=False),
        sa.Column("payload_json", JSON_VARIANT, nullable=False),
        sa.Column("prev_event_hash", sa.String(length=64), nullable=False),
        sa.Column("event_hash", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("sequence_number >= 1", name="ck_audit_events_sequence_number_positive"),
        sa.CheckConstraint("length(prev_event_hash) = 64", name="ck_audit_events_prev_hash_len_64"),
        sa.CheckConstraint("length(event_hash) = 64", name="ck_audit_events_event_hash_len_64"),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["users.id"],
            name="fk_audit_events_actor_user_id_users",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_audit_events_organization_id_organizations",
            ondelete="RESTRICT",
        ),
        sa.PrimaryKeyConstraint("id", name="pk_audit_events"),
        sa.UniqueConstraint("organization_id", "event_hash", name="uq_audit_events_org_hash"),
        sa.UniqueConstraint("organization_id", "sequence_number", name="uq_audit_events_org_seq"),
    )
    op.create_index(
        "ix_audit_events_org_created",
        "audit_events",
        ["organization_id", "created_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index("ix_audit_events_org_created", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_human_reviews_org_docver", table_name="human_reviews")
    op.drop_table("human_reviews")
    op.drop_index("ix_evidence_refs_org_field", table_name="evidence_references")
    op.drop_table("evidence_references")
    op.drop_index("ix_extracted_fields_org_run", table_name="extracted_fields")
    op.drop_table("extracted_fields")
    op.drop_index("ix_processing_runs_org_docver", table_name="processing_runs")
    op.drop_table("processing_runs")
    op.drop_index("ix_doc_versions_org_sha256", table_name="document_versions")
    op.drop_table("document_versions")
    op.drop_index("ix_documents_org_case", table_name="documents")
    op.drop_table("documents")
    op.drop_index("ix_document_cases_org_state", table_name="document_cases")
    op.drop_table("document_cases")
    op.drop_index("ix_org_memberships_org_role", table_name="organization_memberships")
    op.drop_table("organization_memberships")
    op.drop_table("users")
    op.drop_table("organizations")
