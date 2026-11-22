"""Tests for config hardening, OIDC/RBAC prep, processing contracts, deps sync and logging."""

from __future__ import annotations

import ast
import io
import logging
import re
import subprocess
import sys
from pathlib import Path

import pytest

from app.core.config import ConfigurationError, load_settings, mask_database_url
from app.core.constants import ExtractedFieldStatus, OrganizationRole
from app.core.logging import SanitizingFilter, build_safe_log_extra, configure_logging
from app.core.processing_contracts import (
    ExtractionOutcomeStatus,
    NormalizedBoundingBox,
    ReprocessingPolicyContract,
    UnimplementedOcrAdapter,
    compute_processing_idempotency_key,
)
from app.core.oidc import OidcNotConfiguredError, StandardOidcProviderAdapter
from app.core.rbac import (
    AuthenticatedSessionPrincipal,
    AuthorizationDeniedError,
    AuthorizedTenantPrincipal,
    RbacPermission,
    permissions_for_role,
    require_tenant_permission,
)
from app.schemas.tenant import (
    DocumentCreateInput,
    DocumentVersionCreateInput,
    ExtractedFieldCreateInput,
    OrganizationCreateInput,
    ProcessingRunCreateInput,
    TenantContext,
)
from app.services.institutional_service import InstitutionalService


def _valid_prod_env(**overrides: str) -> dict[str, str]:
    base = {
        "JYXIA_ENV": "production",
        "JYXIA_DEBUG": "false",
        "JYXIA_LOG_LEVEL": "INFO",
        "JYXIA_DATABASE_URL": "postgresql+psycopg://jyxia_app:Str0ng_Prod_T3st_Secr3t!@127.0.0.1:5432/jyxia_prod",
        "JYXIA_ALLOW_LOCAL_SYNTHETIC_STORAGE": "false",
        "JYXIA_OIDC_ENABLED": "true",
        "JYXIA_OIDC_ALLOW_HTTP_DEV": "false",
        "JYXIA_OIDC_ISSUER": "https://idp.exemplo.invalid",
        "JYXIA_OIDC_CLIENT_ID": "jyxia-prod-client",
        "JYXIA_OIDC_CLIENT_SECRET": "Prod_Oidc_Client_Secr3t_V4lue_9981!",
        "JYXIA_OIDC_REDIRECT_URI": "https://app.exemplo.invalid/api/v1/auth/callback",
        "JYXIA_APP_BASE_URL": "https://app.exemplo.invalid",
        "JYXIA_SESSION_SECRET": "Prod_Session_Hmac_Aead_Key_8877665544332211!",
        "JYXIA_CSRF_SECRET": "Prod_Csrf_Hmac_Key_11223344556677889900!",
        "JYXIA_SESSION_COOKIE_SECURE": "true",
        "JYXIA_CORS_ALLOWED_ORIGINS": "https://app.exemplo.invalid",
    }
    base.update(overrides)
    return base


def test_environment_configuration_fail_closed_and_dsn_masking() -> None:
    settings = load_settings(
        {
            "JYXIA_ENV": "development",
            "JYXIA_DATABASE_URL": "postgresql+psycopg://jyxia:TOP_SECRET_PASS@127.0.0.1:5432/jyxia_dev?sslmode=require",
        }
    )
    assert "TOP_SECRET_PASS" not in settings.masked_database_url()
    assert "TOP_SECRET_PASS" not in repr(settings)
    assert settings.masked_database_url() == "postgresql+psycopg://127.0.0.1:5432/jyxia_dev"

    # URI masking edge cases
    assert mask_database_url(None) == "<unconfigured>"
    assert mask_database_url("sqlite:///foo/bar.sqlite3") == "sqlite://<local>"
    assert "pwd99" not in mask_database_url("postgresql+psycopg://user:pwd99@localhost:5433/prod?password=xyz")
    assert "xyz" not in mask_database_url("postgresql+psycopg://user:pwd99@127.0.0.1:5433/prod?password=xyz")

    # Reject missing strict DB or invalid schemes
    with pytest.raises(ConfigurationError):
        load_settings({}, strict_database=True)
    with pytest.raises(ConfigurationError):
        load_settings({"JYXIA_DATABASE_URL": "mysql://user:pass@127.0.0.1/db"})
    with pytest.raises(ConfigurationError):
        load_settings({"JYXIA_OIDC_ENABLED": "true", "JYXIA_OIDC_ISSUER": "http://insecure.local"})

    # Production mode accepts complete non-placeholder settings
    prod = load_settings(_valid_prod_env())
    assert prod.env == "production"

    # Production mode must reject all insecure combinations, missing secrets, and hyphen/underscore variants
    insecure_cases = [
        {"JYXIA_DATABASE_URL": "sqlite:///local.db"},
        {"JYXIA_ALLOW_LOCAL_SYNTHETIC_STORAGE": "true"},
        {"JYXIA_DEBUG": "true"},
        {"JYXIA_LOG_LEVEL": "DEBUG"},
        {"JYXIA_OIDC_ENABLED": "false"},
        {"JYXIA_CORS_ALLOWED_ORIGINS": "*"},
        {"JYXIA_CORS_ALLOWED_ORIGINS": "http://insecure-app.local"},
        {"JYXIA_CORS_ALLOWED_ORIGINS": "https://127.0.0.1:8443"},
        {"JYXIA_DATABASE_URL": "postgresql+psycopg://jyxia:SYNTHETIC_LOCAL_ONLY_CHANGE_ME@127.0.0.1:5432/db"},
        {"JYXIA_DATABASE_URL": "postgresql+psycopg://jyxia:short@127.0.0.1:5432/db"},
        {"JYXIA_DATABASE_URL": "postgresql+psycopg://postgres:Str0ng_Prod_T3st_Secr3t!@127.0.0.1:5432/db"},
        {"JYXIA_DATABASE_URL": "postgresql+psycopg://jyxia_migrator:Str0ng_Prod_T3st_Secr3t!@127.0.0.1:5432/db"},
        {"JYXIA_OIDC_ALLOW_HTTP_DEV": "true"},
        {"JYXIA_SESSION_COOKIE_SECURE": "false"},
        {"JYXIA_SESSION_SECRET": ""},
        {"JYXIA_CSRF_SECRET": ""},
        {"JYXIA_SESSION_SECRET": "", "JYXIA_CSRF_SECRET": ""},
        {"JYXIA_SESSION_SECRET": "short-secret"},
        {"JYXIA_SESSION_SECRET": "jyxia-dev-only-ephemeral-session-secret-not-for-production"},
        {"JYXIA_CSRF_SECRET": "jyxia-dev-only-ephemeral-csrf-secret-not-for-production"},
        {"JYXIA_SESSION_SECRET": "custom-dev-only-hyphenated-secret-value-32-chars-min"},
        {"JYXIA_SESSION_SECRET": "custom_dev_only_underscore_secret_value_32_chars_min"},
        {"JYXIA_SESSION_SECRET": "custom-not-for-production-secret-value-32-chars-min"},
        {"JYXIA_CSRF_SECRET": "custom-change-me-hyphenated-csrf-secret-32-chars-min"},
        {"JYXIA_CSRF_SECRET": "SYNTHETIC_LOCAL_ONLY_CHANGE_ME_CSRF_001"},
        {
            "JYXIA_SESSION_SECRET": "Identical_Strong_Secret_Value_For_Both_Session_And_Csrf_99!",
            "JYXIA_CSRF_SECRET": "Identical_Strong_Secret_Value_For_Both_Session_And_Csrf_99!",
        },
        {"JYXIA_OIDC_MFA_REQUIRED": "false"},
        {"JYXIA_OIDC_REQUIRE_BOTH_ACR_AND_AMR": "false"},
        {"JYXIA_OIDC_ALLOWED_AMR": "pwd,otp"},
        {"JYXIA_OIDC_ALLOWED_AMR": "email,totp"},
        {"JYXIA_OIDC_ISSUER": "https://localhost/realms/prod"},
        {"JYXIA_OIDC_ISSUER": "https://10.0.0.1/realms/prod"},
        {"JYXIA_OIDC_REDIRECT_URI": "https://127.0.0.1/api/v1/auth/callback"},
        {"JYXIA_APP_BASE_URL": "https://localhost:8443"},
    ]
    for patch in insecure_cases:
        with pytest.raises(ConfigurationError, match="Invalid JYXIA backend configuration"):
            load_settings(_valid_prod_env(**patch))

    # Omitting JYXIA_SESSION_SECRET or JYXIA_CSRF_SECRET keys completely from environ must fail closed
    env_without_sess = _valid_prod_env()
    del env_without_sess["JYXIA_SESSION_SECRET"]
    with pytest.raises(ConfigurationError, match="Invalid JYXIA backend configuration"):
        load_settings(env_without_sess)

    env_without_csrf = _valid_prod_env()
    del env_without_csrf["JYXIA_CSRF_SECRET"]
    with pytest.raises(ConfigurationError, match="Invalid JYXIA backend configuration"):
        load_settings(env_without_csrf)

    env_without_both = _valid_prod_env()
    del env_without_both["JYXIA_SESSION_SECRET"]
    del env_without_both["JYXIA_CSRF_SECRET"]
    with pytest.raises(ConfigurationError, match="Invalid JYXIA backend configuration"):
        load_settings(env_without_both)


def test_staging_environment_enforces_strict_fail_closed_policy() -> None:
    valid_staging = load_settings(_valid_prod_env(JYXIA_ENV="staging"))
    assert valid_staging.env == "staging"
    assert valid_staging.session_cookie_secure is True
    assert valid_staging.oidc_require_both_acr_and_amr is True

    staging_Missing_secrets = _valid_prod_env(JYXIA_ENV="staging")
    del staging_Missing_secrets["JYXIA_SESSION_SECRET"]
    with pytest.raises(ConfigurationError):
        load_settings(staging_Missing_secrets)

    for bad_staging_patch in [
        {"JYXIA_ENV": "staging", "JYXIA_DEBUG": "true"},
        {"JYXIA_ENV": "staging", "JYXIA_LOG_LEVEL": "DEBUG"},
        {"JYXIA_ENV": "staging", "JYXIA_DATABASE_URL": "sqlite:///staging.db"},
        {"JYXIA_ENV": "staging", "JYXIA_ALLOW_LOCAL_SYNTHETIC_STORAGE": "true"},
        {"JYXIA_ENV": "staging", "JYXIA_OIDC_ENABLED": "false"},
        {"JYXIA_ENV": "staging", "JYXIA_OIDC_MFA_REQUIRED": "false"},
        {"JYXIA_ENV": "staging", "JYXIA_OIDC_REQUIRE_BOTH_ACR_AND_AMR": "false"},
        {"JYXIA_ENV": "staging", "JYXIA_SESSION_COOKIE_SECURE": "false"},
        {"JYXIA_ENV": "staging", "JYXIA_SESSION_SECRET": "jyxia-dev-only-ephemeral-session-secret-not-for-production"},
        {"JYXIA_ENV": "staging", "JYXIA_CSRF_SECRET": "staging-dev-only-weak-csrf-secret-value-0001"},
        {"JYXIA_ENV": "staging", "JYXIA_CORS_ALLOWED_ORIGINS": "*"},
        {"JYXIA_ENV": "staging", "JYXIA_APP_BASE_URL": "http://staging.exemplo.invalid"},
        {"JYXIA_ENV": "staging", "JYXIA_OIDC_ISSUER": "https://127.0.0.1/realms/staging"},
    ]:
        with pytest.raises(ConfigurationError):
            load_settings(_valid_prod_env(**bad_staging_patch))


def test_rbac_and_oidc_fail_closed_for_unconfigured_and_cross_org() -> None:
    from datetime import datetime, timezone
    from app.core.rbac import ROLE_DESCRIPTIONS

    assert OrganizationRole.DOCUMENT_REVIEWER.value == "document_reviewer"
    assert OrganizationRole.DOCUMENT_REVIEWER is OrganizationRole.CLINICAL_REVIEWER
    assert OrganizationRole.ADMINISTRATIVE_REVIEWER is OrganizationRole.DOCUMENT_REVIEWER
    assert OrganizationRole("document_reviewer") is OrganizationRole.DOCUMENT_REVIEWER
    assert OrganizationRole("clinical_reviewer") is OrganizationRole.DOCUMENT_REVIEWER
    assert OrganizationRole("administrative_reviewer") is OrganizationRole.DOCUMENT_REVIEWER
    assert "Administrative Document Reviewer" in ROLE_DESCRIPTIONS[OrganizationRole.DOCUMENT_REVIEWER]
    assert "zero clinical" in ROLE_DESCRIPTIONS[OrganizationRole.DOCUMENT_REVIEWER]

    unconfigured_settings = load_settings({})
    adapter = StandardOidcProviderAdapter(unconfigured_settings)
    with pytest.raises(OidcNotConfiguredError):
        adapter.build_authorization_url(state="s", nonce="n", code_verifier="v" * 44)

    now = datetime.now(timezone.utc)
    sess_ok = AuthenticatedSessionPrincipal(
        session_id="sess-1",
        user_id="user-1",
        external_identity_id="ext-1",
        issuer="https://idp.exemplo.invalid",
        subject="sub-1",
        email="rev@exemplo.invalid",
        display_name="Reviewer",
        mfa_verified=True,
        mfa_verified_at=now,
        auth_time=now,
        acr="urn:jyxia:loa:mfa",
        amr=("pwd", "otp"),
        selected_organization_id="org-a",
    )
    authorized = AuthorizedTenantPrincipal(
        session=sess_ok,
        organization_id="org-a",
        membership_id="mem-1",
        role=OrganizationRole.CLINICAL_REVIEWER,
        permissions=permissions_for_role(OrganizationRole.CLINICAL_REVIEWER),
    )
    require_tenant_permission(
        authorized,
        RbacPermission.HUMAN_REVIEW_WRITE,
        target_organization_id="org-a",
    )

    with pytest.raises(AuthorizationDeniedError):
        require_tenant_permission(
            authorized,
            RbacPermission.CASE_READ,
            target_organization_id="org-b",
        )

    sess_no_mfa = AuthenticatedSessionPrincipal(
        session_id="sess-2",
        user_id="user-2",
        external_identity_id="ext-2",
        issuer="https://idp.exemplo.invalid",
        subject="sub-2",
        email="nomfa@exemplo.invalid",
        display_name="No MFA",
        mfa_verified=False,
        mfa_verified_at=now,
        auth_time=now,
        acr="urn:jyxia:loa:mfa",
        amr=("pwd",),
        selected_organization_id="org-a",
    )
    no_mfa = AuthorizedTenantPrincipal(
        session=sess_no_mfa,
        organization_id="org-a",
        membership_id="mem-2",
        role=OrganizationRole.CLINICAL_REVIEWER,
        permissions=permissions_for_role(OrganizationRole.CLINICAL_REVIEWER),
    )
    with pytest.raises(AuthorizationDeniedError):
        require_tenant_permission(
            no_mfa,
            RbacPermission.HUMAN_REVIEW_WRITE,
            target_organization_id="org-a",
        )


def test_processing_contracts_bounds_idempotency_and_ocr_refusal() -> None:
    bbox = NormalizedBoundingBox(x=0.1, y=0.2, w=0.5, h=0.05)
    assert bbox.w == 0.5
    with pytest.raises(ValueError):
        NormalizedBoundingBox(x=1.2, y=0.0, w=0.1, h=0.1)
    with pytest.raises(ValueError):
        NormalizedBoundingBox(x=0.8, y=0.2, w=0.4, h=0.1)
    with pytest.raises(ValueError):
        NormalizedBoundingBox(x=0.1, y=0.9, w=0.2, h=0.2)

    assert ExtractionOutcomeStatus.OCR_UNAVAILABLE.value == "ocr_unavailable"
    policy = ReprocessingPolicyContract()
    assert policy.preserve_prior_runs is True
    assert policy.preserve_human_reviews is True

    k1 = compute_processing_idempotency_key(
        organization_id="org-1",
        document_version_id="ver-1",
        sha256_hex="a" * 64,
        extractor_version="ext-1",
        policy_version="3.2.0",
    )
    k2 = compute_processing_idempotency_key(
        organization_id="org-1",
        document_version_id="ver-2",
        sha256_hex="a" * 64,
        extractor_version="ext-1",
        policy_version="3.2.0",
    )
    assert len(k1) == 64 and k1 != k2

    with pytest.raises(NotImplementedError):
        UnimplementedOcrAdapter().extract_ocr(b"%PDF-1.4\n%%EOF", mime_type="application/pdf")


def test_logging_sanitization_redacts_secrets_tokens_and_nested_pii() -> None:
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
            nested={"client_secret": "shh_nested", "birth_date": "1990-01-01", "safe": "ok"},
            dsn="postgresql+psycopg://u:SECRET99@127.0.0.1:5432/jyxia",
        )
        assert extra["document_text"] == "[REDACTED]"
        assert extra["raw_value"] == "[REDACTED]"
        assert extra["dsn"] == "[REDACTED]"
        assert extra["nested"]["client_secret"] == "[REDACTED]"
        assert extra["nested"]["birth_date"] == "[REDACTED]"
        assert extra["nested"]["safe"] == "ok"

        fake_jwt = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJzeW4tMSJ9.sigpart123"
        logger.info(
            f"Attempt Bearer secret_abc123 token={fake_jwt} for "
            "postgresql+psycopg://user:pwd123@127.0.0.1:5432/db cpf 123.456.789-00",
            extra=extra,
        )
    finally:
        logger.removeHandler(capture_handler)

    rendered = stream.getvalue()
    assert "secret_abc123" not in rendered
    assert "sigpart123" not in rendered
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


def test_dependencies_single_source_of_truth_and_no_secrets() -> None:
    repo_root = Path(__file__).resolve().parents[2]
    sync_res = subprocess.run(
        [sys.executable, str(repo_root / "tools" / "sync_backend_deps.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert sync_res.returncode == 0, sync_res.stderr or sync_res.stdout

    runtime_text = (repo_root / "backend" / "requirements.txt").read_text(encoding="utf-8")
    assert "pytest" not in runtime_text
    assert "pip-audit" not in runtime_text
    assert "ruff" not in runtime_text

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
