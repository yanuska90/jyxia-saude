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

    # 3. Password-only MFA bypass (["pwd"], no MFA acr/amr, stale auth_time, missing auth_time)
    pwd_only_claims = _base_claims(nonce=raw_nonce, acr="urn:jyxia:loa:mfa", amr=["pwd"])
    with pytest.raises(OidcAuthenticationError, match="Password-only"):
        adapter.verify_id_token(
            _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=pwd_only_claims),
            expected_nonce_hash=expected_nonce_hash,
            nonce_secret=settings.session_secret,
        )

    no_mfa_claims = _base_claims(nonce=raw_nonce, acr="1", amr=[])
    with pytest.raises(OidcAuthenticationError, match="MFA"):
        adapter.verify_id_token(
            _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=no_mfa_claims),
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

    # 5. JWKS key rotation + unknown kid cooldown prevents upstream JWKS DoS
    rot_priv, rot_jwk = _gen_rsa_jwk("rsa-key-2")
    idp.jwks_keys = [idp.rsa_jwk, rot_jwk]
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
    # Cooldown window (15s) allows at most 1 forced JWKS refresh across the 5 invalid kid attempts
    assert (idp.jwks_calls - calls_before) <= 1


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

        # Outage during login fails closed with 503 & logs OIDC_PROVIDER_UNAVAILABLE
        idp.fail_discovery = True
        fresh_adapter = StandardOidcProviderAdapter(settings, transport=idp.transport())
        app_outage = create_app(settings, engine=migrated_engine, oidc_adapter=fresh_adapter)
        with TestClient(app_outage, base_url="http://127.0.0.1:8000") as outage_client:
            out_resp = outage_client.get("/api/v1/auth/login", follow_redirects=False)
            assert out_resp.status_code == 503

        # MFA bypass header/query parameter attempts without session MUST fail 401
        unauth_client = TestClient(app, base_url="http://127.0.0.1:8000")
        assert (
            unauth_client.get(
                "/api/v1/me?mfa_verified=true",
                headers={"X-MFA-Verified": "true", "Authorization": f"Bearer {idp.issued_codes['code-1']['id_token']}"},
            ).status_code
            == 401
        )
        assert SecurityAuditRepository.verify_chain(factory())
