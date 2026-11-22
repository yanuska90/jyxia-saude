"""Security tests for OIDC discovery, JWKS, PKCE S256, token claims separation, and MFA policy."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

import jwt
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import Settings
from app.core.constants import OrganizationRole
from app.core.oidc import (
    OidcAuthenticationError,
    StandardOidcProviderAdapter,
)
from app.core.session_crypto import hmac_token_digest
from app.db.session import create_session_factory
from app.main import create_app
from app.models.entities import OidcAuthState
from app.repositories.identity import IdentityAndSessionRepository, SecurityAuditRepository
from app.repositories.institutional import OrganizationRepository
from app.schemas.tenant import TenantContext
from tests.backend.oidc_test_support import (
    MockOidcProviderState,
    _base_claims,
    _gen_rsa_jwk,
    _oidc_settings,
    _sign_id_token,
)


def _seed_provisioned_user(migrated_engine, *, issuer: str, subject: str, email: str = "admin@jyxia.local"):
    factory = create_session_factory(migrated_engine)
    session = factory()
    try:
        org = OrganizationRepository.create_organization(
            session, slug="org-alpha", name="Organizacao Alpha"
        )
        user = OrganizationRepository.create_user(
            session,
            email=email,
            display_name="Usuario Institucional Alpha",
            mfa_enrolled=True,
        )
        OrganizationRepository.assign_membership(
            session,
            TenantContext(organization_id=org.id),
            user_id=user.id,
            role=OrganizationRole.ORG_ADMIN.value,
        )
        ext = IdentityAndSessionRepository.bind_external_identity(
            session,
            user_id=user.id,
            issuer=issuer,
            subject=subject,
            email_at_binding=email,
        )
        session.commit()
        return org.id, user.id, ext.id
    finally:
        session.close()


def test_unconfigured_oidc_fails_closed_with_503(migrated_engine) -> None:
    app = create_app(Settings(env="test", oidc_enabled=False), engine=migrated_engine)
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        assert client.get("/api/v1/auth/login", follow_redirects=False).status_code == 503
        assert client.get("/api/v1/auth/callback?code=c&state=s", follow_redirects=False).status_code == 503


def test_oidc_token_and_mfa_validation_rejects_all_tampered_and_weak_tokens() -> None:
    idp = MockOidcProviderState()
    idp.jwks_keys = [idp.rsa_jwk, idp.ec_jwk]
    settings = _oidc_settings()
    adapter = StandardOidcProviderAdapter(settings, transport=idp.transport())
    raw_nonce = "nonce-secure-123456"
    expected_nonce_hash = hmac_token_digest(
        raw_nonce, secret=settings.session_secret, context="oidc_nonce"
    )

    # 1. Valid RS256 and valid ES256 tokens succeed
    rs_token = _sign_id_token(
        idp.rsa_priv,
        alg="RS256",
        kid=idp.rsa_jwk["kid"],
        claims=_base_claims(nonce=raw_nonce),
    )
    verified_rs = adapter.verify_id_token(
        rs_token, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
    )
    assert verified_rs.subject == "idp-sub-1"
    assert verified_rs.amr == ("pwd", "otp")

    es_token = _sign_id_token(
        idp.ec_priv,
        alg="ES256",
        kid=idp.ec_jwk["kid"],
        claims=_base_claims(nonce=raw_nonce, sub="idp-sub-ec"),
    )
    verified_es = adapter.verify_id_token(
        es_token, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
    )
    assert verified_es.subject == "idp-sub-ec"

    # 2. Access Token confused with ID Token must NEVER pass (at+jwt & token_use=access)
    at_jwt = _sign_id_token(
        idp.rsa_priv,
        alg="RS256",
        kid=idp.rsa_jwk["kid"],
        claims=_base_claims(nonce=raw_nonce),
        headers={"typ": "at+jwt"},
    )
    with pytest.raises(OidcAuthenticationError, match="Access token"):
        adapter.verify_id_token(
            at_jwt, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
        )

    tok_use_access = _sign_id_token(
        idp.rsa_priv,
        alg="RS256",
        kid=idp.rsa_jwk["kid"],
        claims={**_base_claims(nonce=raw_nonce), "token_use": "access"},
    )
    with pytest.raises(OidcAuthenticationError, match="Access token"):
        adapter.verify_id_token(
            tok_use_access, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
        )

    # 3. Password-only and weak/missing second-factor MFA bypass attempts MUST fail closed
    for rejected_mfa_claims, expected_match in [
        (_base_claims(nonce=raw_nonce, acr="urn:jyxia:loa:mfa", amr=["pwd"]), "Password-only"),
        (_base_claims(nonce=raw_nonce, acr="urn:jyxia:loa:mfa", amr=[]), "non-empty amr"),
        (_base_claims(nonce=raw_nonce, acr="2", amr=[]), "non-empty amr"),
        (_base_claims(nonce=raw_nonce, acr="urn:jyxia:loa:mfa", amr=["pwd", "email"]), "second-factor"),
        (_base_claims(nonce=raw_nonce, acr="urn:jyxia:loa:mfa", amr=["email", "sms"]), "second-factor"),
        (_base_claims(nonce=raw_nonce, acr=None, amr=["pwd", "otp"]), "acr"),
        (_base_claims(nonce=raw_nonce, acr="1", amr=["pwd", "otp"]), "acr"),
        (_base_claims(nonce=raw_nonce, acr="1", amr=[]), "amr"),
    ]:
        with pytest.raises(OidcAuthenticationError, match=expected_match):
            adapter.verify_id_token(
                _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=rejected_mfa_claims),
                expected_nonce_hash=expected_nonce_hash,
                nonce_secret=settings.session_secret,
            )

    old_auth_claims = _base_claims(
        nonce=raw_nonce,
        auth_time=int((datetime.now(timezone.utc) - timedelta(hours=5)).timestamp()),
    )
    with pytest.raises(OidcAuthenticationError, match="max_auth_age"):
        adapter.verify_id_token(
            _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=old_auth_claims),
            expected_nonce_hash=expected_nonce_hash,
            nonce_secret=settings.session_secret,
        )

    missing_auth_time = _base_claims(nonce=raw_nonce)
    del missing_auth_time["auth_time"]
    with pytest.raises(OidcAuthenticationError, match="auth_time"):
        adapter.verify_id_token(
            _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=missing_auth_time),
            expected_nonce_hash=expected_nonce_hash,
            nonce_secret=settings.session_secret,
        )

    # 4. Claims tampering: wrong issuer, wrong aud, multi-aud wrong azp, expired, bad nonce, alg=none, rogue key
    now_ts = int(datetime.now(timezone.utc).timestamp())
    bad_cases = [
        _base_claims(issuer="https://evil.idp.invalid", nonce=raw_nonce),
        _base_claims(aud="other-client", nonce=raw_nonce),
        {**_base_claims(aud=["jyxia-test-client", "other"], nonce=raw_nonce), "azp": "other"},
        {**_base_claims(nonce=raw_nonce), "exp": now_ts - 180},
        {**_base_claims(nonce=raw_nonce), "nbf": now_ts + 300},
        _base_claims(nonce="wrong-nonce"),
    ]
    for bad in bad_cases:
        tok = _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=bad)
        with pytest.raises(OidcAuthenticationError):
            adapter.verify_id_token(
                tok, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
            )

    rogue_priv, _ = _gen_rsa_jwk("rsa-key-1")
    rogue_tok = _sign_id_token(
        rogue_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=_base_claims(nonce=raw_nonce)
    )
    with pytest.raises(OidcAuthenticationError):
        adapter.verify_id_token(
            rogue_tok, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
        )

    alg_none_tok = jwt.encode(_base_claims(nonce=raw_nonce), None, algorithm=None)
    with pytest.raises(OidcAuthenticationError, match="Prohibited"):
        adapter.verify_id_token(
            alg_none_tok, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
        )

    hs_tok = jwt.encode(
        _base_claims(nonce=raw_nonce),
        "shared-secret-key-for-hmac-downgrade-test",
        algorithm="HS256",
        headers={"kid": idp.rsa_jwk["kid"]},
    )
    with pytest.raises(OidcAuthenticationError, match="Prohibited"):
        adapter.verify_id_token(
            hs_tok, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
        )

    # 5. Positive JWKS key rotation + unknown kid cooldown prevents upstream JWKS DoS
    rot_priv, rot_jwk = _gen_rsa_jwk("rsa-key-2")
    idp.jwks_keys = [idp.rsa_jwk, rot_jwk]
    calls_before_rot = idp.jwks_calls
    rotated_tok = _sign_id_token(
        rot_priv,
        alg="RS256",
        kid="rsa-key-2",
        claims=_base_claims(nonce=raw_nonce, sub="idp-sub-rotated"),
    )
    verified_rot = adapter.verify_id_token(
        rotated_tok, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
    )
    assert verified_rot.subject == "idp-sub-rotated"
    assert idp.jwks_calls == calls_before_rot + 1

    # Cooldown triggered immediately on unknown kids without bombing certs endpoint every request
    calls_before = idp.jwks_calls
    for i in range(5):
        with pytest.raises(OidcAuthenticationError):
            unknown_tok = _sign_id_token(
                rot_priv, alg="RS256", kid=f"unknown-{i}", claims=_base_claims(nonce=raw_nonce)
            )
            adapter.verify_id_token(
                unknown_tok, expected_nonce_hash=expected_nonce_hash, nonce_secret=settings.session_secret
            )
    # Because forced refresh just occurred for rsa-key-2, cooldown window (15s) blocks further forced refreshes
    assert (idp.jwks_calls - calls_before) == 0


def test_pkce_encryption_at_rest_state_replay_and_outage_fail_closed(migrated_engine) -> None:
    idp = MockOidcProviderState()
    settings = _oidc_settings()
    adapter = StandardOidcProviderAdapter(settings, transport=idp.transport())
    _seed_provisioned_user(migrated_engine, issuer=idp.issuer, subject="sub-pkce-1")
    app = create_app(settings, engine=migrated_engine, oidc_adapter=adapter)
    factory = create_session_factory(migrated_engine)

    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        login_resp = client.get("/api/v1/auth/login?next=/dashboard", follow_redirects=False)
        assert login_resp.status_code == 302
        auth_url = urlparse(login_resp.headers["location"])
        params = parse_qs(auth_url.query)
        state = params["state"][0]
        nonce = params["nonce"][0]
        challenge = params["code_challenge"][0]
        assert params["code_challenge_method"][0] == "S256"
        assert params["acr_values"][0] == "urn:jyxia:loa:mfa"

        # DB must store state/nonce ONLY as digests and PKCE verifier ONLY encrypted
        db = factory()
        try:
            row = db.scalar(select(OidcAuthState))
            assert row is not None
            assert row.state_hash != state
            assert row.nonce_hash != nonce
            assert state not in row.code_verifier_ciphertext
            assert len(row.state_hash) == 64
        finally:
            db.close()

        # Tampered Login CSRF tx cookie rejected
        tampered_client = TestClient(app, base_url="http://127.0.0.1:8000")
        bad_tx_resp = tampered_client.get(
            f"/api/v1/auth/callback?code=code-1&state={state}",
            follow_redirects=False,
        )
        assert bad_tx_resp.status_code == 401

        # Issue real signed token linked to this PKCE challenge + nonce
        idp.issued_codes["code-1"] = {
            "code_challenge": challenge,
            "id_token": _sign_id_token(
                idp.rsa_priv,
                alg="RS256",
                kid=idp.rsa_jwk["kid"],
                claims=_base_claims(sub="sub-pkce-1", nonce=nonce),
            ),
        }

        cb_resp = client.get(
            f"/api/v1/auth/callback?code=code-1&state={state}",
            follow_redirects=False,
        )
        assert cb_resp.status_code == 302
        assert cb_resp.headers["location"] == "/dashboard"

        # State replay with exact same code & state MUST fail 401!
        replay_resp = client.get(
            f"/api/v1/auth/callback?code=code-1&state={state}",
            follow_redirects=False,
        )
        assert replay_resp.status_code == 401

        # Unknown/forged state WITH matching jyxia_oidc_tx cookie MUST fail 401!
        forged_state = "forged-unknown-state-value-123456"
        forged_tx = hmac_token_digest(
            forged_state, secret=settings.csrf_secret, context="oidc_tx_cookie"
        )
        client.cookies.set("jyxia_oidc_tx", forged_tx, path="/api/v1/auth")
        assert (
            client.get(
                f"/api/v1/auth/callback?code=code-1&state={forged_state}",
                follow_redirects=False,
            ).status_code
            == 401
        )

        # Wrong PKCE challenge / code reuse on fresh login MUST fail 401!
        login_bad_pkce = client.get("/api/v1/auth/login", follow_redirects=False)
        params_bad_pkce = parse_qs(urlparse(login_bad_pkce.headers["location"]).query)
        st_bad_pkce = params_bad_pkce["state"][0]
        idp.issued_codes["code-wrong-pkce"] = {
            "code_challenge": "mismatched_pkce_challenge_value_0000000000000",
            "id_token": _sign_id_token(
                idp.rsa_priv,
                alg="RS256",
                kid=idp.rsa_jwk["kid"],
                claims=_base_claims(sub="sub-pkce-1", nonce=params_bad_pkce["nonce"][0]),
            ),
        }
        assert (
            client.get(
                f"/api/v1/auth/callback?code=code-wrong-pkce&state={st_bad_pkce}",
                follow_redirects=False,
            ).status_code
            == 401
        )

        # Outage during JWKS or Token exchange fails closed with 503
        login_jwks_down = client.get("/api/v1/auth/login", follow_redirects=False)
        params_jwks = parse_qs(urlparse(login_jwks_down.headers["location"]).query)
        idp.issued_codes["code-jwks-down"] = {
            "code_challenge": params_jwks["code_challenge"][0],
            "id_token": _sign_id_token(
                idp.rsa_priv,
                alg="RS256",
                kid="unseen-kid-forcing-jwks-fetch",
                claims=_base_claims(sub="sub-pkce-1", nonce=params_jwks["nonce"][0]),
            ),
        }
        idp.fail_jwks = True
        fresh_jwks_adapter = StandardOidcProviderAdapter(settings, transport=idp.transport())
        app_jwks_down = create_app(settings, engine=migrated_engine, oidc_adapter=fresh_jwks_adapter)
        with TestClient(app_jwks_down, base_url="http://127.0.0.1:8000") as jwks_client:
            jwks_client.cookies.set(
                "jyxia_oidc_tx",
                login_jwks_down.cookies.get("jyxia_oidc_tx") or "",
                path="/api/v1/auth",
            )
            assert (
                jwks_client.get(
                    f"/api/v1/auth/callback?code=code-jwks-down&state={params_jwks['state'][0]}",
                    follow_redirects=False,
                ).status_code
                == 503
            )
        idp.fail_jwks = False

        # Outage during login fails closed with 503 & logs OIDC_PROVIDER_UNAVAILABLE
        idp.fail_discovery = True
        fresh_adapter = StandardOidcProviderAdapter(settings, transport=idp.transport())
        app_outage = create_app(settings, engine=migrated_engine, oidc_adapter=fresh_adapter)
        with TestClient(app_outage, base_url="http://127.0.0.1:8000") as outage_client:
            out_resp = outage_client.get("/api/v1/auth/login", follow_redirects=False)
            assert out_resp.status_code == 503

        # MFA bypass header/query parameter attempts without session MUST fail 401
        with TestClient(app, base_url="http://127.0.0.1:8000") as unauth_client:
            assert (
                unauth_client.get(
                    "/api/v1/me?mfa_verified=true",
                    headers={
                        "X-MFA-Verified": "true",
                        "Authorization": f"Bearer {idp.issued_codes['code-1']['id_token']}",
                    },
                ).status_code
                == 401
            )
        with factory() as verify_session:
            assert SecurityAuditRepository.verify_chain(verify_session)


def test_oidc_anti_ssrf_blocks_private_ips_redirects_userinfo_and_dns_rebinding() -> None:
    import httpx

    idp = MockOidcProviderState(issuer="https://idp.public.jyxia.invalid/realms/main")

    # 1. Public HTTPS issuer with public DNS resolution succeeds
    public_settings = _oidc_settings(
        oidc_issuer="https://idp.public.jyxia.invalid/realms/main",
        oidc_redirect_uri="https://app.public.jyxia.invalid/api/v1/auth/callback",
        oidc_post_logout_redirect_uri="https://app.public.jyxia.invalid/",
        oidc_allow_http_dev=False,
    )
    adapter_ok = StandardOidcProviderAdapter(
        public_settings,
        transport=idp.transport(),
        dns_resolver=lambda _host, _port: ("93.184.216.34",),
    )
    meta = adapter_ok.get_metadata()
    assert meta.issuer == "https://idp.public.jyxia.invalid/realms/main"

    # 2. Private, loopback, link-local, IPv6 loopback/link-local and userinfo URLs rejected when dev HTTP is off
    forbidden_issuers = [
        "https://localhost/realms/main",
        "https://127.0.0.1/realms/main",
        "https://[::1]/realms/main",
        "https://10.0.0.1/realms/main",
        "https://172.16.0.1/realms/main",
        "https://192.168.1.1/realms/main",
        "https://169.254.169.254/latest/meta-data",
        "https://[fe80::1]/realms/main",
        "https://admin:secret@idp.public.jyxia.invalid/realms/main",
    ]
    for bad_iss in forbidden_issuers:
        st_bad = public_settings.model_copy(update={"oidc_issuer": bad_iss})
        ad_bad = StandardOidcProviderAdapter(st_bad, transport=idp.transport())
        with pytest.raises(OidcAuthenticationError):
            ad_bad.get_metadata()

    with pytest.raises(Exception, match="userinfo"):
        _oidc_settings(
            oidc_issuer="https://admin:secret@idp.public.jyxia.invalid/realms/main",
            oidc_redirect_uri="https://app.public.jyxia.invalid/api/v1/auth/callback",
            oidc_post_logout_redirect_uri="https://app.public.jyxia.invalid/",
            oidc_allow_http_dev=False,
        )

    # 3. DNS returning mixed public + private/link-local IPs MUST be rejected
    for bad_dns_ips in [
        ("93.184.216.34", "10.0.0.12"),
        ("93.184.216.34", "127.0.0.1"),
        ("93.184.216.34", "169.254.169.254"),
        ("93.184.216.34", "fe80::1"),
    ]:
        ad_mixed_dns = StandardOidcProviderAdapter(
            public_settings,
            transport=idp.transport(),
            dns_resolver=lambda _h, _p, ips=bad_dns_ips: ips,
        )
        with pytest.raises(OidcAuthenticationError, match="private or non-global"):
            ad_mixed_dns.get_metadata()

    # 4. DNS rebinding between discovery (public IP) and JWKS/token exchange (private or rebound IP) rejected
    active_dns_priv = [("93.184.216.34",)]

    ad_rebind_priv = StandardOidcProviderAdapter(
        public_settings,
        transport=idp.transport(),
        dns_resolver=lambda _host, _port: active_dns_priv[0],
    )
    ad_rebind_priv.get_metadata()
    active_dns_priv[0] = ("169.254.169.254",)
    with pytest.raises(OidcAuthenticationError, match="private or non-global"):
        ad_rebind_priv.exchange_authorization_code(code="any", code_verifier="v" * 48)

    active_dns_disjoint = [("93.184.216.34",)]

    ad_rebind_disjoint = StandardOidcProviderAdapter(
        public_settings,
        transport=idp.transport(),
        dns_resolver=lambda _host, _port: active_dns_disjoint[0],
    )
    ad_rebind_disjoint.get_metadata()
    active_dns_disjoint[0] = ("1.1.1.1",)
    with pytest.raises(OidcAuthenticationError, match="DNS rebinding"):
        ad_rebind_disjoint.exchange_authorization_code(code="any", code_verifier="v" * 48)

    # 5. Discovery returning private/cross-origin JWKS URI or token endpoint or HTTP 302 redirect rejected
    for tampered_doc in [
        {
            "issuer": public_settings.oidc_issuer,
            "authorization_endpoint": f"{public_settings.oidc_issuer}/auth",
            "token_endpoint": f"{public_settings.oidc_issuer}/token",
            "jwks_uri": "https://169.254.169.254/latest/jwks",
        },
        {
            "issuer": public_settings.oidc_issuer,
            "authorization_endpoint": f"{public_settings.oidc_issuer}/auth",
            "token_endpoint": "https://10.0.0.9/token",
            "jwks_uri": f"{public_settings.oidc_issuer}/certs",
        },
        {
            "issuer": public_settings.oidc_issuer,
            "authorization_endpoint": f"{public_settings.oidc_issuer}/auth",
            "token_endpoint": "https://other-host.jyxia.invalid/token",
            "jwks_uri": f"{public_settings.oidc_issuer}/certs",
        },
    ]:
        ad_tampered = StandardOidcProviderAdapter(
            public_settings,
            transport=httpx.MockTransport(lambda _req, doc=tampered_doc: httpx.Response(200, json=doc)),
            dns_resolver=lambda _h, _p: ("93.184.216.34",),
        )
        with pytest.raises(OidcAuthenticationError):
            ad_tampered.get_metadata()

    ad_redirect = StandardOidcProviderAdapter(
        public_settings,
        transport=httpx.MockTransport(
            lambda _req: httpx.Response(302, headers={"Location": "https://169.254.169.254/meta"})
        ),
        dns_resolver=lambda _h, _p: ("93.184.216.34",),
    )
    with pytest.raises(OidcAuthenticationError, match="redirect"):
        ad_redirect.get_metadata()

    # 6. Local Keycloak on loopback HTTP is allowed ONLY in development/test with oidc_allow_http_dev=True
    kc_dev_idp = MockOidcProviderState(issuer="http://127.0.0.1:8080/realms/jyxia-dev")
    kc_dev_settings = _oidc_settings(
        env="test",
        oidc_allow_http_dev=True,
        oidc_issuer="http://127.0.0.1:8080/realms/jyxia-dev",
    )
    ad_kc_dev = StandardOidcProviderAdapter(kc_dev_settings, transport=kc_dev_idp.transport())
    assert ad_kc_dev.get_metadata().issuer == "http://127.0.0.1:8080/realms/jyxia-dev"


def _build_ephemeral_tls_contexts(cert_dns_name: str):
    """Generate an ephemeral CA + server leaf X.509 cert containing ONLY DNSName(cert_dns_name) (zero IP SAN)."""
    from datetime import datetime, timedelta, timezone
    import ssl
    import tempfile
    from pathlib import Path
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "JYXIA Ephemeral OIDC Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cert_dns_name)])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cert_dns_name)]),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )

    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("ascii")
    leaf_pem = leaf_cert.public_bytes(serialization.Encoding.PEM)
    leaf_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    client_ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cadata=ca_pem)
    client_ctx.check_hostname = True
    client_ctx.verify_mode = ssl.CERT_REQUIRED

    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    with tempfile.TemporaryDirectory() as tmp_dir:
        cert_file = Path(tmp_dir) / "leaf.pem"
        cert_file.write_bytes(leaf_pem + b"\n" + leaf_key_pem)
        server_ctx.load_cert_chain(certfile=str(cert_file))

    return server_ctx, client_ctx


def test_oidc_pinned_http_transport_real_tls_sni_and_toctou_immunity() -> None:
    """Prove real TCP socket IP pinning, TLS SNI + X.509 hostname verification, and TOCTOU elimination (ACH-07)."""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import json
    import ssl
    import threading
    import httpcore
    import httpx
    from app.core.oidc import OidcProviderUnavailableError, _PinnedOidcNetworkBackend

    target_hostname = "idp.pinned-tls.jyxia.invalid"
    server_ctx, client_ctx = _build_ephemeral_tls_contexts(target_hostname)
    observed_sni: list[str | None] = []
    observed_hosts: list[str | None] = []
    observed_peer_ips: list[str] = []
    server_mode = {"redirect": False}

    def _on_sni(ssl_sock, sni_name: str | None, _ssl_ctx) -> None:
        observed_sni.append(sni_name)

    server_ctx.sni_callback = _on_sni

    class _OidcTlsHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:  # noqa: A002
            return None

        def do_GET(self) -> None:
            observed_hosts.append(self.headers.get("Host"))
            observed_peer_ips.append(str(self.client_address[0]))
            if server_mode["redirect"]:
                self.send_response(302)
                self.send_header("Location", "https://169.254.169.254/latest/meta-data")
                self.end_headers()
                return
            issuer_url = f"https://{target_hostname}:{self.server.server_port}/realms/tls"
            body = json.dumps(
                {
                    "issuer": issuer_url,
                    "authorization_endpoint": f"{issuer_url}/auth",
                    "token_endpoint": f"{issuer_url}/token",
                    "jwks_uri": f"{issuer_url}/certs",
                }
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _OidcTlsHandler)
    port = httpd.server_port
    httpd.socket = server_ctx.wrap_socket(httpd.socket, server_side=True)
    server_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    server_thread.start()

    try:
        issuer_url = f"https://{target_hostname}:{port}/realms/tls"
        tls_settings = _oidc_settings(
            env="test",
            oidc_issuer=issuer_url,
            oidc_redirect_uri="https://app.public.jyxia.invalid/api/v1/auth/callback",
            oidc_post_logout_redirect_uri="https://app.public.jyxia.invalid/",
            oidc_allow_http_dev=False,
        )

        # Teste A & Teste B & Teste E — Real TCP socket connects to pinned IP without a 2nd DNS resolution,
        # while preserving original hostname for TLS SNI and X.509 certificate hostname verification!
        dns_call_count = 0

        def _single_shot_dns_resolver(host: str, resolved_port: int):
            nonlocal dns_call_count
            dns_call_count += 1
            assert host == target_hostname
            assert resolved_port == port
            if dns_call_count == 1:
                return ("127.0.0.1",)
            # If httpcore ever performed a 2nd DNS lookup when opening the TCP socket, return forbidden IP!
            return ("169.254.169.254",)

        adapter_tls = StandardOidcProviderAdapter(
            tls_settings,
            dns_resolver=_single_shot_dns_resolver,
            ssl_context=client_ctx,
            allow_loopback_target_in_test=True,
        )
        metadata = adapter_tls.get_metadata()
        assert metadata.issuer == issuer_url
        # DNS resolver was invoked ONLY once during pre-validation; socket connected directly to pinned IP!
        assert dns_call_count == 1
        assert len(adapter_tls.connection_history) == 1
        conn_rec = adapter_tls.connection_history[0]
        assert conn_rec.transport_mode == "pinned_tcp_socket"
        assert conn_rec.requested_host == target_hostname
        assert conn_rec.port == port
        assert conn_rec.connected_ip == "127.0.0.1"
        assert conn_rec.tls_server_hostname == target_hostname
        assert conn_rec.tls_established is True
        assert observed_sni[-1] == target_hostname
        assert observed_hosts[-1] == f"{target_hostname}:{port}"
        assert observed_peer_ips[-1] == "127.0.0.1"

        # Teste B part 2: When a subsequent call (_fetch_jwks) re-validates DNS and DNS now returns
        # private IP 169.254.169.254, it is rejected BEFORE opening any new TCP socket!
        with pytest.raises(OidcAuthenticationError, match="private or non-global"):
            adapter_tls._fetch_jwks()
        assert len(adapter_tls.connection_history) == 1

        # Teste E part 2: Certificate hostname mismatch (cert issued for wrong-host.jyxia.invalid) MUST fail TLS verification!
        wrong_server_ctx, wrong_client_ctx = _build_ephemeral_tls_contexts("wrong-host.jyxia.invalid")
        httpd_wrong = ThreadingHTTPServer(("127.0.0.1", 0), _OidcTlsHandler)
        wrong_port = httpd_wrong.server_port
        httpd_wrong.socket = wrong_server_ctx.wrap_socket(httpd_wrong.socket, server_side=True)
        wrong_thread = threading.Thread(target=httpd_wrong.serve_forever, daemon=True)
        wrong_thread.start()
        try:
            wrong_settings = tls_settings.model_copy(
                update={"oidc_issuer": f"https://{target_hostname}:{wrong_port}/realms/tls"}
            )
            adapter_wrong_cert = StandardOidcProviderAdapter(
                wrong_settings,
                dns_resolver=lambda _h, _p: ("127.0.0.1",),
                ssl_context=wrong_client_ctx,
                allow_loopback_target_in_test=True,
            )
            with pytest.raises(OidcProviderUnavailableError):
                adapter_wrong_cert.get_metadata()
        finally:
            httpd_wrong.shutdown()
            httpd_wrong.server_close()

        # Weakened SSLContext (check_hostname=False or CERT_NONE) MUST be rejected by constructor
        weak_ctx = ssl.create_default_context()
        weak_ctx.check_hostname = False
        with pytest.raises(OidcAuthenticationError, match="check_hostname"):
            StandardOidcProviderAdapter(tls_settings, ssl_context=weak_ctx)

        # Teste F — Real TLS server responding with 302 redirect to private IP MUST be rejected
        server_mode["redirect"] = True
        adapter_real_redirect = StandardOidcProviderAdapter(
            tls_settings,
            dns_resolver=lambda _h, _p: ("127.0.0.1",),
            ssl_context=client_ctx,
            allow_loopback_target_in_test=True,
        )
        with pytest.raises(OidcAuthenticationError, match="redirect"):
            adapter_real_redirect.get_metadata()

        # Teste C & Teste D — Private IP or mixed public+private DNS results rejected with ZERO socket connections
        for rejected_ips in [
            ("127.0.0.1",),
            ("169.254.169.254",),
            ("10.0.0.1",),
            ("93.184.216.34", "169.254.169.254"),
        ]:
            ad_c_d = StandardOidcProviderAdapter(
                tls_settings,
                dns_resolver=lambda _h, _p, ips=rejected_ips: ips,
                ssl_context=client_ctx,
                allow_loopback_target_in_test=False,
            )
            with pytest.raises(OidcAuthenticationError):
                ad_c_d.get_metadata()
            assert len(ad_c_d.connection_history) == 0

        # Teste G — Injected transport prohibited in production/staging and cannot bypass checks in test
        for strict_env in ("production", "staging"):
            strict_settings = tls_settings.model_copy(update={"env": strict_env})
            with pytest.raises(OidcAuthenticationError, match="prohibited in production and staging"):
                StandardOidcProviderAdapter(
                    strict_settings,
                    transport=httpx.MockTransport(lambda _r: httpx.Response(200)),
                )
            with pytest.raises(OidcAuthenticationError, match="prohibited in production and staging"):
                StandardOidcProviderAdapter(
                    strict_settings,
                    dns_resolver=lambda _h, _p: ("93.184.216.34",),
                )
            with pytest.raises(OidcAuthenticationError, match="prohibited in production and staging"):
                StandardOidcProviderAdapter(
                    strict_settings,
                    allow_loopback_target_in_test=True,
                )

        # In test with oidc_allow_http_dev=False and injected MockTransport, missing DNS resolution for
        # non-existent domain MUST NOT be silently skipped (fails closed via socket.getaddrinfo)
        ad_injected_no_dns = StandardOidcProviderAdapter(
            tls_settings,
            transport=httpx.MockTransport(lambda _r: httpx.Response(200, json={"issuer": issuer_url})),
        )
        with pytest.raises(OidcProviderUnavailableError, match="DNS resolution failed"):
            ad_injected_no_dns.get_metadata()
        assert len(ad_injected_no_dns.connection_history) == 0

        # Teste H — NetworkBackend refuses unpinned authorities and invalidates pinned hosts cleanly
        net_backend = _PinnedOidcNetworkBackend(adapter_tls)
        with pytest.raises(httpcore.ConnectError, match="unpinned OIDC authority"):
            net_backend.connect_tcp("unapproved.authority.jyxia.invalid", 443)
        adapter_tls.invalidate_pinned_hosts()
        assert adapter_tls.get_pinned_ips(target_hostname, port) == ()
        with pytest.raises(httpcore.ConnectError, match="unpinned OIDC authority"):
            net_backend.connect_tcp(target_hostname, port)
    finally:
        httpd.shutdown()
        httpd.server_close()
