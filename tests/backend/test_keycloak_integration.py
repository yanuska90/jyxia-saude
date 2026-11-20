"""Real end-to-end integration test against Keycloak 26.8.2 (OIDC PKCE + TOTP MFA) & PG jyxia_app."""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import os
import re
import struct
import time
from urllib.parse import urljoin, urlparse

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app.core.config import Settings
from app.core.constants import CSRF_COOKIE_NAME, CSRF_HEADER_NAME, CaseReadinessState, OrganizationRole
from app.core.oidc import StandardOidcProviderAdapter
from app.db.session import create_session_factory
from app.main import create_app
from app.repositories.identity import IdentityAndSessionRepository, SecurityAuditRepository
from app.repositories.institutional import CaseAndDocumentRepository, OrganizationRepository
from app.schemas.tenant import TenantContext

_FORM_ACTION_RE = re.compile(r'<form[^>]+action="([^"]+)"', re.IGNORECASE)


def _generate_totp(base32_secret: str, *, for_time: int | None = None, step: int = 30) -> str:
    padded = base32_secret.strip().upper().replace(" ", "")
    padded += "=" * ((8 - len(padded) % 8) % 8)
    key = base64.b32decode(padded, casefold=True)
    counter = int((for_time if for_time is not None else time.time()) // step)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{code_int % 1_000_000:06d}"


def _extract_form_action(html_body: str, base_url: str) -> str:
    match = _FORM_ACTION_RE.search(html_body)
    assert match is not None, f"Expected HTML form action in Keycloak response:\n{html_body[:1000]}"
    action = html.unescape(match.group(1))
    return urljoin(base_url, action)


def _complete_keycloak_login(
    kc_http: httpx.Client,
    auth_url: str,
    *,
    username: str,
    password: str,
    totp_secret: str | None = None,
) -> str:
    """Drive real Keycloak HTML auth form + optional TOTP form, returning callback redirect URL."""
    page1 = kc_http.get(auth_url, follow_redirects=False)
    assert page1.status_code == 200, f"Unexpected Keycloak login page status {page1.status_code}"
    action1 = _extract_form_action(page1.text, str(page1.url))

    step2 = kc_http.post(
        action1,
        data={"username": username, "password": password, "credentialId": ""},
        follow_redirects=False,
    )
    if step2.status_code in {302, 303}:
        # Password-only flow/client completed without OTP form
        return step2.headers["location"]

    assert step2.status_code == 200, f"Expected Keycloak OTP challenge or redirect, got {step2.status_code}"
    assert totp_secret is not None, "Keycloak challenged for OTP without totp_secret configured."
    action2 = _extract_form_action(step2.text, str(step2.url))

    otp_code = _generate_totp(totp_secret)
    step3 = kc_http.post(
        action2,
        data={"otp": otp_code},
        follow_redirects=False,
    )
    assert step3.status_code in {302, 303}, f"Expected callback redirect after OTP, got {step3.status_code}: {step3.text[:500]}"
    return step3.headers["location"]


@pytest.mark.skipif(
    not os.environ.get("JYXIA_KEYCLOAK_E2E_URL", "").strip(),
    reason="Live Keycloak 26.8.2 instance (JYXIA_KEYCLOAK_E2E_URL) required for real IdP E2E.",
)
def test_real_keycloak_oidc_pkce_totp_mfa_and_pg_runtime_e2e(migrated_engine, app_engine) -> None:
    kc_issuer = os.environ["JYXIA_KEYCLOAK_E2E_URL"].rstrip("/")
    client_id = os.environ["JYXIA_KEYCLOAK_CLIENT_ID"]
    client_secret = os.environ["JYXIA_KEYCLOAK_CLIENT_SECRET"]

    mfa_sub = os.environ["JYXIA_KEYCLOAK_MFA_USER_SUB"]
    mfa_username = os.environ["JYXIA_KEYCLOAK_MFA_USERNAME"]
    mfa_password = os.environ["JYXIA_KEYCLOAK_MFA_PASSWORD"]
    mfa_totp_secret = os.environ["JYXIA_KEYCLOAK_MFA_TOTP_SECRET"]

    unbound_username = os.environ["JYXIA_KEYCLOAK_UNBOUND_USERNAME"]
    unbound_password = os.environ["JYXIA_KEYCLOAK_UNBOUND_PASSWORD"]
    unbound_totp_secret = os.environ["JYXIA_KEYCLOAK_UNBOUND_TOTP_SECRET"]

    pwd_only_client_id = os.environ["JYXIA_KEYCLOAK_PWD_ONLY_CLIENT_ID"]
    pwd_only_client_secret = os.environ["JYXIA_KEYCLOAK_PWD_ONLY_CLIENT_SECRET"]

    # Seed Org + User + ExternalIdentity ONLY for provisioned user via owner engine
    owner_factory = create_session_factory(migrated_engine)
    owner_db = owner_factory()
    try:
        org = OrganizationRepository.create_organization(owner_db, slug="kc-org", name="Keycloak Org")
        user = OrganizationRepository.create_user(
            owner_db,
            email=f"{mfa_username}@jyxia.local",
            display_name="Keycloak Verified User",
            mfa_enrolled=True,
        )
        OrganizationRepository.assign_membership(
            owner_db,
            TenantContext(organization_id=org.id),
            user_id=user.id,
            role=OrganizationRole.ORG_ADMIN.value,
        )
        IdentityAndSessionRepository.bind_external_identity(
            owner_db,
            user_id=user.id,
            issuer=kc_issuer,
            subject=mfa_sub,
            email_at_binding=user.email,
        )
        CaseAndDocumentRepository.create_case(
            owner_db,
            TenantContext(organization_id=org.id),
            case_code="KC-CASE-001",
            external_reference="EXT-KC-1",
            procedure_reference=None,
            declared_laterality=None,
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        owner_db.commit()
    finally:
        owner_db.close()

    # Boot JYXIA app strictly with least-privilege runtime DB engine (`jyxia_app`)!
    settings = Settings(
        env="development",
        app_base_url="http://127.0.0.1:8000",
        oidc_enabled=True,
        oidc_allow_http_dev=True,
        oidc_issuer=kc_issuer,
        oidc_client_id=client_id,
        oidc_client_secret=client_secret,
        oidc_redirect_uri="http://127.0.0.1:8000/api/v1/auth/callback",
        oidc_post_logout_redirect_uri="http://127.0.0.1:8000/",
        oidc_mfa_required=True,
        oidc_allowed_acr=("urn:jyxia:loa:mfa",),
        oidc_allowed_amr=("otp", "totp", "hwk", "fido", "webauthn", "mfa"),
        oidc_max_auth_age_seconds=3600,
        session_secret="CI_Ephemeral_Session_Secret_32_Bytes_Minimum_Value_1!",
        csrf_secret="CI_Ephemeral_Csrf_Secret_32_Bytes_Minimum_Value_1234!",
        session_cookie_secure=False,
    )
    app = create_app(
        settings,
        engine=app_engine,
        oidc_adapter=StandardOidcProviderAdapter(settings),
    )

    # 1. Valid Keycloak Password + TOTP MFA -> Callback -> Session -> Protected Org Data -> Logout
    with TestClient(app, base_url="http://127.0.0.1:8000") as bff_client, httpx.Client() as kc_http:
        login_res = bff_client.get("/api/v1/auth/login?next=/workspace", follow_redirects=False)
        assert login_res.status_code == 302
        callback_url = _complete_keycloak_login(
            kc_http,
            login_res.headers["location"],
            username=mfa_username,
            password=mfa_password,
            totp_secret=mfa_totp_secret,
        )
        cb_parsed = urlparse(callback_url)
        cb_res = bff_client.get(f"{cb_parsed.path}?{cb_parsed.query}", follow_redirects=False)
        assert cb_res.status_code == 302
        assert cb_res.headers["location"] == "/workspace"

        sess = bff_client.get("/api/v1/auth/session")
        assert sess.status_code == 200
        assert sess.json()["acr"] == "urn:jyxia:loa:mfa"
        assert "otp" in sess.json()["amr"]

        me = bff_client.get("/api/v1/me")
        assert me.status_code == 200
        assert me.json()["user_id"] == user.id

        cases = bff_client.get(f"/api/v1/organizations/{org.id}/cases")
        assert cases.status_code == 200
        assert cases.json()["cases"][0]["case_code"] == "KC-CASE-001"

        csrf_val = bff_client.cookies.get(CSRF_COOKIE_NAME)
        assert csrf_val
        logout_res = bff_client.post(
            "/api/v1/auth/logout",
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_val},
        )
        assert logout_res.status_code == 200
        assert logout_res.json()["logged_out"] is True
        assert bff_client.get("/api/v1/me").status_code == 401

    # 2. Authenticated unbound Keycloak user with MFA -> JYXIA rejects 403 & NEVER auto-provisions
    with TestClient(app, base_url="http://127.0.0.1:8000") as unbound_bff, httpx.Client() as kc_http_2:
        login_res = unbound_bff.get("/api/v1/auth/login", follow_redirects=False)
        callback_url = _complete_keycloak_login(
            kc_http_2,
            login_res.headers["location"],
            username=unbound_username,
            password=unbound_password,
            totp_secret=unbound_totp_secret,
        )
        cb_parsed = urlparse(callback_url)
        cb_res = unbound_bff.get(f"{cb_parsed.path}?{cb_parsed.query}", follow_redirects=False)
        assert cb_res.status_code == 403

    # 3. Password-only Keycloak client lacking OTP/LoA=2 -> JYXIA rejects fail-closed 401!
    pwd_only_settings = Settings(
        env="development",
        app_base_url="http://127.0.0.1:8000",
        oidc_enabled=True,
        oidc_allow_http_dev=True,
        oidc_issuer=kc_issuer,
        oidc_client_id=pwd_only_client_id,
        oidc_client_secret=pwd_only_client_secret,
        oidc_redirect_uri="http://127.0.0.1:8000/api/v1/auth/callback",
        oidc_mfa_required=True,
        oidc_allowed_acr=("urn:jyxia:loa:mfa",),
        oidc_allowed_amr=("otp", "totp", "hwk", "fido", "webauthn", "mfa"),
        session_secret=settings.session_secret,
        csrf_secret=settings.csrf_secret,
        session_cookie_secure=False,
    )
    app_pwd_only = create_app(
        pwd_only_settings,
        engine=app_engine,
        oidc_adapter=StandardOidcProviderAdapter(pwd_only_settings),
    )
    with TestClient(app_pwd_only, base_url="http://127.0.0.1:8000") as weak_bff, httpx.Client() as kc_http_3:
        login_res = weak_bff.get("/api/v1/auth/login", follow_redirects=False)
        callback_url = _complete_keycloak_login(
            kc_http_3,
            login_res.headers["location"],
            username=mfa_username,
            password=mfa_password,
            totp_secret=None,
        )
        cb_parsed = urlparse(callback_url)
        cb_res = weak_bff.get(f"{cb_parsed.path}?{cb_parsed.query}", follow_redirects=False)
        assert cb_res.status_code == 401

    # Confirm security ledger integrity after live Keycloak run
    verify_db = owner_factory()
    try:
        assert SecurityAuditRepository.verify_chain(verify_db)
        user_count = verify_db.execute(text("SELECT count(*) FROM users")).scalar()
        assert user_count == 1
    finally:
        verify_db.close()
