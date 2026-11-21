"""Real end-to-end integration test against Keycloak 26.8.2 (OIDC PKCE + TOTP MFA) & PG jyxia_app."""

from __future__ import annotations

import base64
import email.message
import hashlib
import hmac
import html
import http.cookiejar as http_cookiejar
import os
import struct
import time
import urllib.request
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlsplit

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

_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1"})


class _LoopbackSecureCookiePolicy(http_cookiejar.DefaultCookiePolicy):
    """Mirror W3C Secure Context browser behavior for loopback HTTP origins (127.0.0.1/localhost).

    Keycloak 26 marks AUTH_SESSION_ID with Secure on loopback origins; stdlib CookieJar omits
    Secure cookies over http:// unless the target hostname is explicitly loopback.
    """

    def return_ok_secure(
        self,
        cookie: http_cookiejar.Cookie,
        request: urllib.request.Request,
    ) -> bool:
        host = (urlsplit(request.get_full_url()).hostname or "").lower()
        if host in _LOOPBACK_HOSTS:
            return True
        return super().return_ok_secure(cookie, request)


class _HttpxCookieResponseAdapter:
    """Expose httpx Set-Cookie headers through urllib/http.cookiejar's .info() interface."""

    def __init__(self, headers: httpx.Headers) -> None:
        msg = email.message.Message()
        for value in headers.get_list("set-cookie"):
            msg.add_header("Set-Cookie", value)
        self._msg = msg

    def info(self) -> email.message.Message:
        return self._msg


def _new_loopback_keycloak_client(
    *, transport: httpx.BaseTransport | None = None
) -> tuple[httpx.Client, http_cookiejar.CookieJar]:
    """Create an httpx.Client preserving Secure Keycloak session cookies only on loopback HTTP."""
    jar = http_cookiejar.CookieJar(policy=_LoopbackSecureCookiePolicy())

    def _attach_cookies(request: httpx.Request) -> None:
        urllib_req = urllib.request.Request(
            url=str(request.url),
            headers=dict(request.headers),
            method=request.method,
        )
        jar.add_cookie_header(urllib_req)
        cookie_hdr = urllib_req.get_header("Cookie")
        if cookie_hdr:
            request.headers["Cookie"] = cookie_hdr

    def _store_cookies(response: httpx.Response) -> None:
        urllib_req = urllib.request.Request(
            url=str(response.request.url),
            headers=dict(response.request.headers),
            method=response.request.method,
        )
        jar.extract_cookies(_HttpxCookieResponseAdapter(response.headers), urllib_req)

    kwargs: dict[str, object] = {
        "event_hooks": {"request": [_attach_cookies], "response": [_store_cookies]},
    }
    if transport is not None:
        kwargs["transport"] = transport
    client = httpx.Client(**kwargs)  # type: ignore[arg-type]
    return client, jar


class _KeycloakHtmlParser(HTMLParser):
    """Parse Keycloak login/OTP HTML forms, hidden inputs and page title without fragile regexes."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.forms: list[dict[str, object]] = []
        self._current_form: dict[str, object] | None = None
        self._in_title = False
        self._title_parts: list[str] = []
        self._in_notice = False
        self._notice_parts: list[str] = []

    @property
    def title(self) -> str:
        return " ".join("".join(self._title_parts).split())

    @property
    def notice(self) -> str:
        return " ".join("".join(self._notice_parts).split())[:240]

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag_lower = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        cls = attr_map.get("class", "").lower()
        elem_id = attr_map.get("id", "").lower()
        if tag_lower == "title":
            self._in_title = True
        elif tag_lower == "h1" or "alert" in cls or "feedback" in cls or "instruction" in elem_id or "error" in cls:
            self._in_notice = True
        elif tag_lower == "form":
            self._current_form = {
                "id": attr_map.get("id", ""),
                "action": attr_map.get("action", ""),
                "hidden_inputs": {},
            }
        elif tag_lower == "input" and self._current_form is not None:
            if attr_map.get("type", "").lower() == "hidden" and attr_map.get("name"):
                hidden = self._current_form["hidden_inputs"]
                assert isinstance(hidden, dict)
                hidden[attr_map["name"]] = attr_map.get("value", "")

    def handle_endtag(self, tag: str) -> None:
        tag_lower = tag.lower()
        if tag_lower == "title":
            self._in_title = False
        elif tag_lower in {"h1", "div", "span", "p"}:
            self._in_notice = False
        elif tag_lower == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self._title_parts.append(data)
        if self._in_notice:
            self._notice_parts.append(data)


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


def _extract_keycloak_form(
    html_body: str,
    base_url: str,
    *,
    preferred_form_ids: tuple[str, ...],
) -> tuple[str, dict[str, str], str]:
    parser = _KeycloakHtmlParser()
    parser.feed(html_body)
    parser.close()
    forms = parser.forms
    selected: dict[str, object] | None = None
    for form_id in preferred_form_ids:
        selected = next((f for f in forms if f.get("id") == form_id and f.get("action")), None)
        if selected is not None:
            break
    if selected is None:
        selected = next((f for f in forms if f.get("action")), None)
    assert selected is not None, (
        f"Expected HTML form in Keycloak response (title={parser.title!r}):\n{html_body[:1000]}"
    )
    action = html.unescape(str(selected["action"]))
    hidden = dict(selected["hidden_inputs"])  # type: ignore[arg-type]
    return urljoin(base_url, action), hidden, parser.title


def _describe_keycloak_response(
    resp: httpx.Response,
    jar: http_cookiejar.CookieJar,
) -> str:
    parser = _KeycloakHtmlParser()
    parser.feed(resp.text)
    parser.close()
    cookie_names = sorted({c.name for c in jar})
    path = urlsplit(str(resp.url)).path
    return (
        f"status={resp.status_code} path={path!r} title={parser.title!r} "
        f"notice={parser.notice!r} cookie_names={cookie_names}"
    )


def _complete_keycloak_login(
    kc_http: httpx.Client,
    jar: http_cookiejar.CookieJar,
    auth_url: str,
    *,
    username: str,
    password: str,
    totp_secret: str | None = None,
) -> str:
    """Drive real Keycloak HTML auth form + optional TOTP form, returning callback redirect URL."""
    page1 = kc_http.get(auth_url, follow_redirects=False)
    assert page1.status_code == 200, (
        f"Unexpected Keycloak login page: {_describe_keycloak_response(page1, jar)}"
    )
    action1, hidden1, _ = _extract_keycloak_form(
        page1.text,
        str(page1.url),
        preferred_form_ids=("kc-form-login",),
    )

    login_data = {**hidden1, "username": username, "password": password}
    login_data.setdefault("credentialId", "")
    step2 = kc_http.post(action1, data=login_data, follow_redirects=False)
    if step2.status_code in {302, 303}:
        # Password-only flow/client completed without OTP form
        return step2.headers["location"]

    assert step2.status_code == 200, (
        f"Expected Keycloak OTP challenge or redirect: {_describe_keycloak_response(step2, jar)}"
    )
    assert totp_secret is not None, "Keycloak challenged for OTP without totp_secret configured."
    action2, hidden2, _ = _extract_keycloak_form(
        step2.text,
        str(step2.url),
        preferred_form_ids=("kc-otp-login-form",),
    )

    otp_code = _generate_totp(totp_secret)
    otp_data = {**hidden2, "otp": otp_code}
    step3 = kc_http.post(action2, data=otp_data, follow_redirects=False)
    assert step3.status_code in {302, 303}, (
        f"Expected callback redirect after OTP: {_describe_keycloak_response(step3, jar)}"
    )
    return step3.headers["location"]


def test_loopback_keycloak_http_client_transmits_secure_session_cookies_only_to_loopback() -> None:
    """Verify W3C loopback Secure cookie behavior for Keycloak 26 integration harness."""
    observed: list[tuple[str, str | None, bytes]] = []

    def _handler(request: httpx.Request) -> httpx.Response:
        observed.append((str(request.url), request.headers.get("cookie"), request.content))
        if "protocol/openid-connect/auth" in str(request.url):
            return httpx.Response(
                200,
                headers=[
                    (
                        "set-cookie",
                        "AUTH_SESSION_ID=loop-sess; Path=/realms/jyxia-dev/; Secure; SameSite=None; HttpOnly",
                    ),
                ],
                text=(
                    "<html><head><title>Sign in</title></head><body>"
                    '<form id="kc-form-login" method="post" '
                    'action="http://127.0.0.1:8080/realms/jyxia-dev/login-actions/authenticate?session_code=s1&amp;tab_id=t1">'
                    '<input type="hidden" name="credentialId" value="" />'
                    "</form></body></html>"
                ),
            )
        if "execution=otp" in str(request.url):
            if request.headers.get("cookie") != "AUTH_SESSION_ID=loop-sess":
                return httpx.Response(400, text="<title>Missing session cookie</title>")
            return httpx.Response(
                302,
                headers={"location": "http://127.0.0.1:8000/api/v1/auth/callback?code=c1&state=st"},
            )
        if "login-actions/authenticate" in str(request.url):
            if request.headers.get("cookie") != "AUTH_SESSION_ID=loop-sess":
                return httpx.Response(400, text="<title>Missing session cookie</title>")
            return httpx.Response(
                200,
                text=(
                    "<html><head><title>OTP</title></head><body>"
                    '<form id="kc-otp-login-form" method="post" '
                    'action="http://127.0.0.1:8080/realms/jyxia-dev/login-actions/authenticate?session_code=s1&amp;execution=otp">'
                    '<input type="hidden" name="selectedCredentialId" value="cred-1" />'
                    "</form></body></html>"
                ),
            )
        return httpx.Response(200, text="<title>External</title>")

    client, jar = _new_loopback_keycloak_client(transport=httpx.MockTransport(_handler))
    with client:
        cb = _complete_keycloak_login(
            client,
            jar,
            "http://127.0.0.1:8080/realms/jyxia-dev/protocol/openid-connect/auth?client_id=test",
            username="u1",
            password="p1",
            totp_secret="JBSWY3DPEHPK3PXP",
        )
        assert cb == "http://127.0.0.1:8000/api/v1/auth/callback?code=c1&state=st"
        # External non-loopback HTTP MUST NOT receive Secure cookies
        client.get("http://example.com/realms/jyxia-dev/login-actions/authenticate")

    assert observed[1][:2] == (
        "http://127.0.0.1:8080/realms/jyxia-dev/login-actions/authenticate?session_code=s1&tab_id=t1",
        "AUTH_SESSION_ID=loop-sess",
    )
    assert observed[2][:2] == (
        "http://127.0.0.1:8080/realms/jyxia-dev/login-actions/authenticate?session_code=s1&execution=otp",
        "AUTH_SESSION_ID=loop-sess",
    )
    assert b"selectedCredentialId=cred-1" in observed[2][2]
    assert observed[-1][1] is None


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
        org_id = str(org.id)
        user_id = str(user.id)
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
    kc_http, kc_jar = _new_loopback_keycloak_client()
    with TestClient(app, base_url="http://127.0.0.1:8000") as bff_client, kc_http:
        login_res = bff_client.get("/api/v1/auth/login?next=/workspace", follow_redirects=False)
        assert login_res.status_code == 302
        callback_url = _complete_keycloak_login(
            kc_http,
            kc_jar,
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
        assert me.json()["user_id"] == user_id

        cases = bff_client.get(f"/api/v1/organizations/{org_id}/cases")
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

    # 2. Invalid TOTP code against live Keycloak 26.8.2 MUST be rejected by Keycloak OTP form!
    kc_http_bad_otp, kc_jar_bad_otp = _new_loopback_keycloak_client()
    with TestClient(app, base_url="http://127.0.0.1:8000") as bad_otp_bff, kc_http_bad_otp:
        login_res = bad_otp_bff.get("/api/v1/auth/login", follow_redirects=False)
        assert login_res.status_code == 302
        page1 = kc_http_bad_otp.get(login_res.headers["location"], follow_redirects=False)
        assert page1.status_code == 200
        action1, hidden1, _ = _extract_keycloak_form(
            page1.text, str(page1.url), preferred_form_ids=("kc-form-login",)
        )
        step2 = kc_http_bad_otp.post(
            action1,
            data={**hidden1, "username": mfa_username, "password": mfa_password, "credentialId": ""},
            follow_redirects=False,
        )
        assert step2.status_code == 200
        action2, hidden2, _ = _extract_keycloak_form(
            step2.text, str(step2.url), preferred_form_ids=("kc-otp-login-form",)
        )
        valid_totp_int = int(_generate_totp(mfa_totp_secret))
        wrong_totp_code = f"{(valid_totp_int + 543210) % 1_000_000:06d}"
        bad_otp_step = kc_http_bad_otp.post(
            action2,
            data={**hidden2, "otp": wrong_totp_code},
            follow_redirects=False,
        )
        # Keycloak refuses redirect/code issuance and re-renders OTP challenge (HTTP 200)
        assert bad_otp_step.status_code == 200
        assert "code=" not in str(bad_otp_step.headers.get("location", ""))

    # 3. Authenticated unbound Keycloak user with MFA -> JYXIA rejects 403 & NEVER auto-provisions
    kc_http_2, kc_jar_2 = _new_loopback_keycloak_client()
    with TestClient(app, base_url="http://127.0.0.1:8000") as unbound_bff, kc_http_2:
        login_res = unbound_bff.get("/api/v1/auth/login", follow_redirects=False)
        callback_url = _complete_keycloak_login(
            kc_http_2,
            kc_jar_2,
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
    kc_http_3, kc_jar_3 = _new_loopback_keycloak_client()
    with TestClient(app_pwd_only, base_url="http://127.0.0.1:8000") as weak_bff, kc_http_3:
        login_res = weak_bff.get("/api/v1/auth/login", follow_redirects=False)
        callback_url = _complete_keycloak_login(
            kc_http_3,
            kc_jar_3,
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
