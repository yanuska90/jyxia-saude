"""Tests for config validation, OIDC/RBAC fail-closed prep, contracts and sanitized logging."""

from __future__ import annotations

import ast
import io
import logging
from pathlib import Path

import pytest

from app.core.config import ConfigurationError, load_settings
from app.core.constants import OrganizationRole
from app.core.logging import SanitizingFilter, build_safe_log_extra, configure_logging
from app.core.processing_contracts import NormalizedBoundingBox, UnimplementedOcrAdapter
from app.core.security_prep import (
    AuthenticatedPrincipal,
    AuthenticationNotConfiguredError,
    AuthorizationDeniedError,
    RbacPermission,
    StubOidcAuthenticator,
    require_permission,
)
from app.schemas.tenant import ExtractedFieldCreateInput, OrganizationCreateInput, TenantContext
from app.services.institutional_service import InstitutionalService


def test_environment_configuration_validation_and_dsn_masking() -> None:
    settings = load_settings(
        {
            "JYXIA_ENV": "development",
            "JYXIA_DATABASE_URL": "postgresql+psycopg://jyxia:TOP_SECRET_PASS@127.0.0.1:5432/jyxia_dev",
        }
    )
    assert "TOP_SECRET_PASS" not in settings.masked_database_url()
    assert "TOP_SECRET_PASS" not in repr(settings)
    assert settings.masked_database_url() == "postgresql+psycopg://127.0.0.1:5432/jyxia_dev"

    with pytest.raises(ConfigurationError):
        load_settings({}, strict_database=True)

    with pytest.raises(ConfigurationError):
        load_settings({"JYXIA_DATABASE_URL": "mysql://user:pass@127.0.0.1/db"})

    with pytest.raises(ConfigurationError):
        load_settings({"JYXIA_ENV": "production", "JYXIA_DATABASE_URL": "sqlite:///local.db"})

    with pytest.raises(ConfigurationError):
        load_settings(
            {
                "JYXIA_ENV": "production",
                "JYXIA_DATABASE_URL": "postgresql+psycopg://u:p@127.0.0.1:5432/db",
                "JYXIA_ALLOW_LOCAL_SYNTHETIC_STORAGE": "true",
            }
        )

    with pytest.raises(ConfigurationError):
        load_settings({"JYXIA_OIDC_ENABLED": "true", "JYXIA_OIDC_ISSUER": "http://insecure.local"})


def test_security_prep_fails_closed_for_unconfigured_oidc_and_cross_org() -> None:
    stub = StubOidcAuthenticator()
    with pytest.raises(AuthenticationNotConfiguredError):
        stub.authenticate_bearer_token("fake.jwt.token")

    principal = AuthenticatedPrincipal(
        user_id="user-1",
        organization_id="org-a",
        role=OrganizationRole.CLINICAL_REVIEWER,
        mfa_verified=True,
    )
    require_permission(principal, RbacPermission.HUMAN_REVIEW_WRITE, target_organization_id="org-a")

    with pytest.raises(AuthorizationDeniedError):
        require_permission(None, RbacPermission.CASE_READ, target_organization_id="org-a")

    with pytest.raises(AuthorizationDeniedError):
        require_permission(principal, RbacPermission.CASE_READ, target_organization_id="org-b")

    no_mfa = AuthenticatedPrincipal(
        user_id="user-2",
        organization_id="org-a",
        role=OrganizationRole.CLINICAL_REVIEWER,
        mfa_verified=False,
    )
    with pytest.raises(AuthorizationDeniedError):
        require_permission(no_mfa, RbacPermission.HUMAN_REVIEW_WRITE, target_organization_id="org-a")


def test_processing_contracts_validate_bounds_and_forbid_unimplemented_ocr() -> None:
    bbox = NormalizedBoundingBox(x=0.1, y=0.2, w=0.5, h=0.05)
    assert bbox.w == 0.5
    with pytest.raises(ValueError):
        NormalizedBoundingBox(x=1.2, y=0.0, w=0.1, h=0.1)
    with pytest.raises(NotImplementedError):
        UnimplementedOcrAdapter().extract_ocr_lines(b"%PDF-1.4", mime_type="application/pdf")


def test_logging_sanitization_redacts_secrets_and_payload_keys() -> None:
    logger = configure_logging("INFO")
    stream = io.StringIO()
    capture_handler = logging.StreamHandler(stream)
    capture_handler.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
    capture_handler.addFilter(SanitizingFilter())
    logger.addHandler(capture_handler)
    try:
        extra = build_safe_log_extra(
            organization_id="org-1",
            document_text="CONFIDENTIAL_PDF_BODY_XYZ",
            raw_value="SYNTHETIC_PATIENT_NAME",
            dsn="postgresql+psycopg://u:SECRET99@127.0.0.1:5432/jyxia",
        )
        assert extra["document_text"] == "[REDACTED]"
        assert extra["raw_value"] == "[REDACTED]"
        assert extra["dsn"] == "[REDACTED]"

        logger.info(
            "Attempt Bearer secret_abc123 for postgresql+psycopg://user:pwd123@127.0.0.1:5432/db cpf 123.456.789-00",
            extra=extra,
        )
    finally:
        logger.removeHandler(capture_handler)

    rendered = stream.getvalue()
    assert "secret_abc123" not in rendered
    assert "pwd123" not in rendered
    assert "123.456.789-00" not in rendered
    assert "CONFIDENTIAL_PDF_BODY_XYZ" not in rendered
    assert "SYNTHETIC_PATIENT_NAME" not in rendered
    assert "[REDACTED]" in rendered
    assert "[CPF_REDACTED]" in rendered


def test_service_record_extracted_field_never_logs_raw_value(db_session) -> None:
    org = InstitutionalService.create_organization(
        db_session, OrganizationCreateInput(slug="log-safe-org", name="Log Safe Org")
    )
    ctx = TenantContext(organization_id=org.id)
    from app.core.constants import ExtractedFieldStatus
    from app.schemas.tenant import (
        DocumentCreateInput,
        DocumentVersionCreateInput,
        ProcessingRunCreateInput,
    )

    doc = InstitutionalService.register_document(
        db_session, ctx, DocumentCreateInput(source_label="log_safe_source")
    )
    ver = InstitutionalService.register_document_version(
        db_session,
        ctx,
        DocumentVersionCreateInput(
            document_id=doc.id,
            version_number=1,
            sha256_hex="c" * 64,
            mime_type="application/pdf",
            byte_size=120,
            storage_key=f"{org.id}/{'c' * 32}.pdf",
        ),
    )
    run = InstitutionalService.record_processing_run(
        db_session,
        ctx,
        ProcessingRunCreateInput(
            document_version_id=ver.id,
            policy_version="3.2.0",
            extractor_version="test",
        ),
    )

    logger = configure_logging("INFO")
    stream = io.StringIO()
    handler = logging.StreamHandler(stream)
    handler.addFilter(SanitizingFilter())
    logger.addHandler(handler)
    try:
        InstitutionalService.record_extracted_field(
            db_session,
            ctx,
            ExtractedFieldCreateInput(
                processing_run_id=run.id,
                document_version_id=ver.id,
                field_key="patient",
                raw_value="SYNTHETIC_SECRET_PATIENT_MARKER_8842",
                normalized_value="SYNTHETIC_SECRET_PATIENT_MARKER_8842",
                status=ExtractedFieldStatus.EXTRACTED,
            ),
        )
    finally:
        logger.removeHandler(handler)
    assert "SYNTHETIC_SECRET_PATIENT_MARKER_8842" not in stream.getvalue()


def test_no_real_secrets_or_private_urls_in_backend_and_infra_files() -> None:
    import re

    repo_root = Path(__file__).resolve().parents[2]
    secret_patterns = [
        re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}"),
        re.compile(r"github_pat_[A-Za-z0-9_]{40,}"),
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        re.compile(
            r"postgresql(?:\+psycopg)?://[^:\s]+:[^@\s]+@(?!127\.0\.0\.1|localhost|postgres)[^\s]+"
        ),
    ]
    targets = [
        *(repo_root / "backend").rglob("*.py"),
        repo_root / ".env.example",
        repo_root / "compose.institutional.yaml",
    ]
    for path in targets:
        text = path.read_text(encoding="utf-8")
        for pat in secret_patterns:
            assert not pat.search(text), f"Sensitive pattern matched in {path}"


def test_backend_does_not_import_legacy_v2_modules() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    forbidden_modules = {"legacy", "integration", "vault_crypto", "teleconsultation", "synthetic_import"}
    for file_path in (repo_root / "backend").rglob("*.py"):
        text = file_path.read_text(encoding="utf-8")
        assert "MONGO_PASSWORD" not in text
        assert "JYXIA_API_TOKEN" not in text
        tree = ast.parse(text, filename=str(file_path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top = alias.name.split(".")[0]
                    assert top not in forbidden_modules, f"Forbidden import {alias.name} in {file_path}"
            elif isinstance(node, ast.ImportFrom) and node.module:
                top = node.module.split(".")[0]
                assert top not in forbidden_modules, f"Forbidden import {node.module} in {file_path}"
