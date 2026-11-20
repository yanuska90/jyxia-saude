"""Incremental hardening of tenant composite FKs, bounds checks and audit triggers.

Revision ID: 20261120_0002
Revises: 20261120_0001
Create Date: 2026-11-20 12:45:00+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20261120_0002"
down_revision = "20261120_0001"
branch_labels = None
depends_on = None

AUDIT_SCHEMA_VERSION = "jyxia.audit.v1"

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def _install_audit_triggers(dialect_name: str) -> None:
    if dialect_name == "postgresql":
        op.execute(
            sa.text(
                """
                CREATE OR REPLACE FUNCTION jyxia_forbid_audit_event_mutation()
                RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'audit_events is append-only; % is not permitted', TG_OP;
                END;
                $$ LANGUAGE plpgsql;
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_audit_events_no_update
                BEFORE UPDATE ON audit_events
                FOR EACH ROW EXECUTE FUNCTION jyxia_forbid_audit_event_mutation();
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_audit_events_no_delete
                BEFORE DELETE ON audit_events
                FOR EACH ROW EXECUTE FUNCTION jyxia_forbid_audit_event_mutation();
                """
            )
        )
    elif dialect_name == "sqlite":
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_audit_events_no_update
                BEFORE UPDATE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit_events is append-only; UPDATE is not permitted');
                END;
                """
            )
        )
        op.execute(
            sa.text(
                """
                CREATE TRIGGER trg_audit_events_no_delete
                BEFORE DELETE ON audit_events
                BEGIN
                    SELECT RAISE(ABORT, 'audit_events is append-only; DELETE is not permitted');
                END;
                """
            )
        )


def _drop_audit_triggers(dialect_name: str) -> None:
    if dialect_name == "postgresql":
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_events_no_delete ON audit_events;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_events_no_update ON audit_events;"))
        op.execute(sa.text("DROP FUNCTION IF EXISTS jyxia_forbid_audit_event_mutation();"))
    elif dialect_name == "sqlite":
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_events_no_delete;"))
        op.execute(sa.text("DROP TRIGGER IF EXISTS trg_audit_events_no_update;"))


def upgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name

    with op.batch_alter_table("users", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.create_check_constraint(
            "ck_users_external_subject_nonempty",
            "external_subject IS NULL OR length(trim(external_subject)) >= 1",
        )

    with op.batch_alter_table("document_cases", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column("external_reference", sa.String(length=128), nullable=True))
        batch_op.drop_constraint("fk_document_cases_created_by_user_id_users", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_document_cases_created_by_user_id_users",
            "users",
            ["created_by_user_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_foreign_key(
            "fk_document_cases_org_creator",
            "organization_memberships",
            ["organization_id", "created_by_user_id"],
            ["organization_id", "user_id"],
            ondelete="RESTRICT",
        )
        batch_op.create_check_constraint(
            "ck_document_cases_external_ref_min_len",
            "external_reference IS NULL OR length(trim(external_reference)) >= 2",
        )

    op.create_index(
        "uq_document_cases_org_ext_ref",
        "document_cases",
        ["organization_id", "external_reference"],
        unique=True,
        sqlite_where=sa.text("external_reference IS NOT NULL"),
        postgresql_where=sa.text("external_reference IS NOT NULL"),
    )

    with op.batch_alter_table("documents", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.create_check_constraint(
            "ck_documents_discard_requires_reason",
            "discarded_at IS NULL OR (discard_reason IS NOT NULL AND length(trim(discard_reason)) >= 3)",
        )

    with op.batch_alter_table("document_versions", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column("original_filename", sa.String(length=255), nullable=True))
        batch_op.create_unique_constraint(
            "uq_doc_versions_org_doc_id", ["organization_id", "document_id", "id"]
        )
        batch_op.drop_constraint("fk_doc_versions_org_supersede", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_doc_versions_org_doc_supersede",
            "document_versions",
            ["organization_id", "document_id", "superseded_by_version_id"],
            ["organization_id", "document_id", "id"],
            ondelete="RESTRICT",
        )
        batch_op.drop_constraint("ck_document_versions_sha256_hex_len_64", type_="check")
        batch_op.create_check_constraint(
            "ck_document_versions_sha256_hex_len_64",
            "length(trim(sha256_hex)) = 64 AND sha256_hex = lower(sha256_hex)",
        )
        batch_op.create_check_constraint(
            "ck_document_versions_storage_key_min_len",
            "length(trim(storage_key)) >= 8",
        )
        batch_op.create_check_constraint(
            "ck_document_versions_original_filename_safe",
            "original_filename IS NULL OR "
            "(length(trim(original_filename)) >= 1 "
            "AND replace(original_filename, '/', '') = original_filename "
            "AND replace(original_filename, '\\', '') = original_filename "
            "AND replace(original_filename, '..', '') = original_filename)",
        )

    with op.batch_alter_table("processing_runs", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column("idempotency_key", sa.String(length=128), nullable=True))
        batch_op.create_unique_constraint(
            "uq_processing_runs_org_ver_id",
            ["organization_id", "document_version_id", "id"],
        )
        batch_op.create_unique_constraint(
            "uq_processing_runs_org_idemp",
            ["organization_id", "idempotency_key"],
        )
        batch_op.create_check_constraint(
            "ck_processing_runs_finished_after_started",
            "finished_at IS NULL OR finished_at >= started_at",
        )

    with op.batch_alter_table("extracted_fields", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.create_unique_constraint(
            "uq_extracted_fields_org_ver_id",
            ["organization_id", "document_version_id", "id"],
        )
        batch_op.drop_constraint("fk_extracted_fields_org_run", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_extracted_fields_org_ver_run",
            "processing_runs",
            ["organization_id", "document_version_id", "processing_run_id"],
            ["organization_id", "document_version_id", "id"],
            ondelete="RESTRICT",
        )
        batch_op.drop_constraint("ck_extracted_fields_status_valid", type_="check")
        batch_op.create_check_constraint(
            "ck_extracted_fields_status_valid",
            "status IN ('extracted', 'missing', 'abstained', 'ambiguous', 'unreadable')",
        )
        batch_op.create_check_constraint(
            "ck_extracted_fields_abstained_status_coherent",
            "(status <> 'abstained') OR (abstained = TRUE)",
        )

    with op.batch_alter_table("evidence_references", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.create_unique_constraint(
            "uq_evidence_refs_org_ver_id",
            ["organization_id", "document_version_id", "id"],
        )
        batch_op.drop_constraint("fk_evidence_refs_org_field", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_evidence_refs_org_ver_field",
            "extracted_fields",
            ["organization_id", "document_version_id", "extracted_field_id"],
            ["organization_id", "document_version_id", "id"],
            ondelete="RESTRICT",
        )
        batch_op.create_check_constraint(
            "ck_evidence_references_bbox_x_w_within_page",
            "bbox_x + bbox_w <= 1.00001",
        )
        batch_op.create_check_constraint(
            "ck_evidence_references_bbox_y_h_within_page",
            "bbox_y + bbox_h <= 1.00001",
        )

    with op.batch_alter_table("human_reviews", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("fk_human_reviews_org_evidence", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_human_reviews_org_ver_evidence",
            "evidence_references",
            ["organization_id", "document_version_id", "evidence_reference_id"],
            ["organization_id", "document_version_id", "id"],
            ondelete="RESTRICT",
        )
        batch_op.create_foreign_key(
            "fk_human_reviews_org_reviewer",
            "organization_memberships",
            ["organization_id", "reviewer_user_id"],
            ["organization_id", "user_id"],
            ondelete="RESTRICT",
        )

    with op.batch_alter_table("audit_events", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.add_column(
            sa.Column(
                "schema_version",
                sa.String(length=32),
                nullable=False,
                server_default=sa.text(f"'{AUDIT_SCHEMA_VERSION}'"),
            )
        )
        batch_op.create_foreign_key(
            "fk_audit_events_org_actor",
            "organization_memberships",
            ["organization_id", "actor_user_id"],
            ["organization_id", "user_id"],
            ondelete="RESTRICT",
        )
        batch_op.drop_constraint("ck_audit_events_prev_hash_len_64", type_="check")
        batch_op.create_check_constraint(
            "ck_audit_events_prev_hash_len_64",
            "length(trim(prev_event_hash)) = 64 AND prev_event_hash = lower(prev_event_hash)",
        )
        batch_op.drop_constraint("ck_audit_events_event_hash_len_64", type_="check")
        batch_op.create_check_constraint(
            "ck_audit_events_event_hash_len_64",
            "length(trim(event_hash)) = 64 AND event_hash = lower(event_hash)",
        )
        batch_op.create_check_constraint(
            "ck_audit_events_schema_version_nonempty",
            "length(trim(schema_version)) >= 3",
        )
        batch_op.create_check_constraint(
            "ck_audit_events_event_type_min_len",
            "length(trim(event_type)) >= 2",
        )
        batch_op.create_check_constraint(
            "ck_audit_events_target_entity_min_len",
            "length(trim(target_entity_type)) >= 2",
        )

    _install_audit_triggers(dialect_name)


def downgrade() -> None:
    bind = op.get_bind()
    dialect_name = bind.dialect.name
    _drop_audit_triggers(dialect_name)

    with op.batch_alter_table("audit_events", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_audit_events_target_entity_min_len", type_="check")
        batch_op.drop_constraint("ck_audit_events_event_type_min_len", type_="check")
        batch_op.drop_constraint("ck_audit_events_schema_version_nonempty", type_="check")
        batch_op.drop_constraint("ck_audit_events_event_hash_len_64", type_="check")
        batch_op.create_check_constraint(
            "ck_audit_events_event_hash_len_64",
            "length(event_hash) = 64",
        )
        batch_op.drop_constraint("ck_audit_events_prev_hash_len_64", type_="check")
        batch_op.create_check_constraint(
            "ck_audit_events_prev_hash_len_64",
            "length(prev_event_hash) = 64",
        )
        batch_op.drop_constraint("fk_audit_events_org_actor", type_="foreignkey")
        batch_op.drop_column("schema_version")

    with op.batch_alter_table("human_reviews", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("fk_human_reviews_org_reviewer", type_="foreignkey")
        batch_op.drop_constraint("fk_human_reviews_org_ver_evidence", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_human_reviews_org_evidence",
            "evidence_references",
            ["organization_id", "evidence_reference_id"],
            ["organization_id", "id"],
            ondelete="RESTRICT",
        )

    with op.batch_alter_table("evidence_references", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_evidence_references_bbox_y_h_within_page", type_="check")
        batch_op.drop_constraint("ck_evidence_references_bbox_x_w_within_page", type_="check")
        batch_op.drop_constraint("fk_evidence_refs_org_ver_field", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_evidence_refs_org_field",
            "extracted_fields",
            ["organization_id", "extracted_field_id"],
            ["organization_id", "id"],
            ondelete="RESTRICT",
        )
        batch_op.drop_constraint("uq_evidence_refs_org_ver_id", type_="unique")

    with op.batch_alter_table("extracted_fields", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_extracted_fields_abstained_status_coherent", type_="check")
        batch_op.drop_constraint("ck_extracted_fields_status_valid", type_="check")
        batch_op.create_check_constraint(
            "ck_extracted_fields_status_valid",
            "status IN ('extracted', 'abstained', 'ambiguous', 'unreadable')",
        )
        batch_op.drop_constraint("fk_extracted_fields_org_ver_run", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_extracted_fields_org_run",
            "processing_runs",
            ["organization_id", "processing_run_id"],
            ["organization_id", "id"],
            ondelete="RESTRICT",
        )
        batch_op.drop_constraint("uq_extracted_fields_org_ver_id", type_="unique")

    with op.batch_alter_table("processing_runs", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_processing_runs_finished_after_started", type_="check")
        batch_op.drop_constraint("uq_processing_runs_org_idemp", type_="unique")
        batch_op.drop_constraint("uq_processing_runs_org_ver_id", type_="unique")
        batch_op.drop_column("idempotency_key")

    with op.batch_alter_table("document_versions", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_document_versions_original_filename_safe", type_="check")
        batch_op.drop_constraint("ck_document_versions_storage_key_min_len", type_="check")
        batch_op.drop_constraint("ck_document_versions_sha256_hex_len_64", type_="check")
        batch_op.create_check_constraint(
            "ck_document_versions_sha256_hex_len_64",
            "length(sha256_hex) = 64",
        )
        batch_op.drop_constraint("fk_doc_versions_org_doc_supersede", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_doc_versions_org_supersede",
            "document_versions",
            ["organization_id", "superseded_by_version_id"],
            ["organization_id", "id"],
            ondelete="RESTRICT",
        )
        batch_op.drop_constraint("uq_doc_versions_org_doc_id", type_="unique")
        batch_op.drop_column("original_filename")

    with op.batch_alter_table("documents", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_documents_discard_requires_reason", type_="check")

    op.drop_index("uq_document_cases_org_ext_ref", table_name="document_cases")

    with op.batch_alter_table("document_cases", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_document_cases_external_ref_min_len", type_="check")
        batch_op.drop_constraint("fk_document_cases_org_creator", type_="foreignkey")
        batch_op.drop_constraint("fk_document_cases_created_by_user_id_users", type_="foreignkey")
        batch_op.create_foreign_key(
            "fk_document_cases_created_by_user_id_users",
            "users",
            ["created_by_user_id"],
            ["id"],
            ondelete="SET NULL",
        )
        batch_op.drop_column("external_reference")

    with op.batch_alter_table("users", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_users_external_subject_nonempty", type_="check")
