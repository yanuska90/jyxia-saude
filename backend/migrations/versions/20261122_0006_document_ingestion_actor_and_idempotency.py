"""Add document ingestion actor FKs, transactional idempotency and version immutability guard.

Revision ID: 20261122_0006
Revises: 20261122_0005
Create Date: 2026-11-22 11:45:00+00:00
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "20261122_0006"
down_revision = "20261122_0005"
branch_labels = None
depends_on = None

_NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def _upgrade_pg_document_version_immutability() -> None:
    op.execute(
        sa.text(
            """
            CREATE OR REPLACE FUNCTION public.jyxia_guard_document_version_immutability()
            RETURNS trigger
            LANGUAGE plpgsql
            AS $$
            BEGIN
                IF TG_OP = 'DELETE' THEN
                    RAISE EXCEPTION 'DocumentVersion is immutable once registered and cannot be deleted';
                END IF;

                IF NEW.id IS DISTINCT FROM OLD.id
                   OR NEW.organization_id IS DISTINCT FROM OLD.organization_id
                   OR NEW.document_id IS DISTINCT FROM OLD.document_id
                   OR NEW.version_number IS DISTINCT FROM OLD.version_number
                   OR NEW.sha256_hex IS DISTINCT FROM OLD.sha256_hex
                   OR NEW.mime_type IS DISTINCT FROM OLD.mime_type
                   OR NEW.byte_size IS DISTINCT FROM OLD.byte_size
                   OR NEW.storage_driver IS DISTINCT FROM OLD.storage_driver
                   OR NEW.storage_key IS DISTINCT FROM OLD.storage_key
                   OR NEW.created_at IS DISTINCT FROM OLD.created_at
                THEN
                    RAISE EXCEPTION 'DocumentVersion immutable binary/version attributes cannot be overwritten';
                END IF;

                RETURN NEW;
            END;
            $$;
            """
        )
    )
    op.execute(
        sa.text(
            """
            DROP TRIGGER IF EXISTS trg_document_versions_immutable_core ON public.document_versions;
            CREATE TRIGGER trg_document_versions_immutable_core
            BEFORE UPDATE OR DELETE ON public.document_versions
            FOR EACH ROW
            EXECUTE FUNCTION public.jyxia_guard_document_version_immutability();
            """
        )
    )


def _downgrade_pg_document_version_immutability() -> None:
    op.execute(
        sa.text(
            "DROP TRIGGER IF EXISTS trg_document_versions_immutable_core ON public.document_versions;"
        )
    )
    op.execute(
        sa.text("DROP FUNCTION IF EXISTS public.jyxia_guard_document_version_immutability();")
    )


def upgrade() -> None:
    bind = op.get_bind()

    with op.batch_alter_table("documents", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.add_column(sa.Column("external_reference", sa.String(length=128), nullable=True))
        batch_op.add_column(sa.Column("description", sa.String(length=500), nullable=True))
        batch_op.add_column(sa.Column("created_by_user_id", sa.String(length=36), nullable=True))
        batch_op.add_column(sa.Column("idempotency_key", sa.String(length=128), nullable=True))
        batch_op.add_column(
            sa.Column("idempotency_fingerprint", sa.String(length=64), nullable=True)
        )
        batch_op.create_foreign_key(
            "fk_documents_created_by_user_id_users",
            "users",
            ["created_by_user_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_foreign_key(
            "fk_documents_org_creator",
            "organization_memberships",
            ["organization_id", "created_by_user_id"],
            ["organization_id", "user_id"],
            ondelete="RESTRICT",
        )
        batch_op.create_unique_constraint(
            "uq_documents_org_case_idemp",
            ["organization_id", "case_id", "idempotency_key"],
        )
        batch_op.create_check_constraint(
            "ck_documents_external_ref_min_len",
            "external_reference IS NULL OR length(trim(external_reference)) >= 2",
        )
        batch_op.create_check_constraint(
            "ck_documents_description_nonempty",
            "description IS NULL OR length(trim(description)) >= 1",
        )
        batch_op.create_check_constraint(
            "ck_documents_idempotency_coherent",
            "idempotency_key IS NULL OR (length(trim(idempotency_key)) >= 4 "
            "AND idempotency_fingerprint IS NOT NULL "
            "AND length(trim(idempotency_fingerprint)) = 64 "
            "AND idempotency_fingerprint = lower(idempotency_fingerprint))",
        )

    with op.batch_alter_table(
        "document_versions", naming_convention=_NAMING_CONVENTION
    ) as batch_op:
        batch_op.add_column(sa.Column("created_by_user_id", sa.String(length=36), nullable=True))
        batch_op.create_foreign_key(
            "fk_document_versions_created_by_user_id_users",
            "users",
            ["created_by_user_id"],
            ["id"],
            ondelete="RESTRICT",
        )
        batch_op.create_foreign_key(
            "fk_doc_versions_org_creator",
            "organization_memberships",
            ["organization_id", "created_by_user_id"],
            ["organization_id", "user_id"],
            ondelete="RESTRICT",
        )

    if bind.dialect.name == "postgresql":
        _upgrade_pg_document_version_immutability()


def downgrade() -> None:
    bind = op.get_bind()
    if bind.dialect.name == "postgresql":
        _downgrade_pg_document_version_immutability()

    with op.batch_alter_table(
        "document_versions", naming_convention=_NAMING_CONVENTION
    ) as batch_op:
        batch_op.drop_constraint("fk_doc_versions_org_creator", type_="foreignkey")
        batch_op.drop_constraint(
            "fk_document_versions_created_by_user_id_users", type_="foreignkey"
        )
        batch_op.drop_column("created_by_user_id")

    with op.batch_alter_table("documents", naming_convention=_NAMING_CONVENTION) as batch_op:
        batch_op.drop_constraint("ck_documents_idempotency_coherent", type_="check")
        batch_op.drop_constraint("ck_documents_description_nonempty", type_="check")
        batch_op.drop_constraint("ck_documents_external_ref_min_len", type_="check")
        batch_op.drop_constraint("uq_documents_org_case_idemp", type_="unique")
        batch_op.drop_constraint("fk_documents_org_creator", type_="foreignkey")
        batch_op.drop_constraint("fk_documents_created_by_user_id_users", type_="foreignkey")
        batch_op.drop_column("idempotency_fingerprint")
        batch_op.drop_column("idempotency_key")
        batch_op.drop_column("created_by_user_id")
        batch_op.drop_column("description")
        batch_op.drop_column("external_reference")
