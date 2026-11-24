"""Shared ephemeral OIDC/JWKS/PKCE test helpers (not a test module)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from app.core.config import Settings
from app.core.session_crypto import compute_pkce_s256


def _gen_rsa_jwk(kid: str) -> tuple[Any, dict[str, Any]]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk_dict = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(priv.public_key()))
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    return priv, jwk_dict


def _gen_ec_jwk(kid: str) -> tuple[Any, dict[str, Any]]:
    priv = ec.generate_private_key(ec.SECP256R1())
    jwk_dict = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(priv.public_key()))
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "ES256"
    return priv, jwk_dict


class MockOidcProviderState:
    """Ephemeral in-memory OIDC IdP server supporting real RS256/ES256 JWKS & PKCE checks."""

    def __init__(self, issuer: str = "https://idp.jyxia.local/realms/test") -> None:
        self.issuer = issuer
        self.rsa_priv, self.rsa_jwk = _gen_rsa_jwk("rsa-key-1")
        self.ec_priv, self.ec_jwk = _gen_ec_jwk("ec-key-1")
        self.jwks_keys: list[dict[str, Any]] = [self.rsa_jwk]
        self.discovery_calls = 0
        self.jwks_calls = 0
        self.fail_discovery = False
        self.fail_jwks = False
        self.fail_token = False
        self.discovery_issuer_override: str | None = None
        self.issued_codes: dict[str, dict[str, Any]] = {}
        self.next_id_token_override: str | None = None

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path.endswith("/.well-known/openid-configuration"):
                self.discovery_calls += 1
                if self.fail_discovery:
                    return httpx.Response(503, json={"error": "temporarily_unavailable"})
                return httpx.Response(
                    200,
                    json={
                        "issuer": self.discovery_issuer_override or self.issuer,
                        "authorization_endpoint": f"{self.issuer}/protocol/openid-connect/auth",
                        "token_endpoint": f"{self.issuer}/protocol/openid-connect/token",
                        "jwks_uri": f"{self.issuer}/protocol/openid-connect/certs",
                        "end_session_endpoint": f"{self.issuer}/protocol/openid-connect/logout",
                    },
                )
            if path.endswith("/protocol/openid-connect/certs"):
                self.jwks_calls += 1
                if self.fail_jwks:
                    return httpx.Response(503, json={"error": "jwks_down"})
                return httpx.Response(200, json={"keys": self.jwks_keys})
            if path.endswith("/protocol/openid-connect/token"):
                if self.fail_token:
                    return httpx.Response(502, json={"error": "bad_gateway"})
                body = parse_qs(request.content.decode("utf-8"))
                code = body.get("code", [""])[0]
                code_verifier = body.get("code_verifier", [""])[0]
                record = self.issued_codes.get(code)
                if record is None:
                    return httpx.Response(400, json={"error": "invalid_grant"})
                if compute_pkce_s256(code_verifier) != record["code_challenge"]:
                    return httpx.Response(400, json={"error": "invalid_grant"})
                raw_id = self.next_id_token_override or record["id_token"]
                return httpx.Response(
                    200,
                    json={
                        "access_token": "opaque_unused_access_tok",
                        "id_token": raw_id,
                        "token_type": "Bearer",
                        "expires_in": 300,
                    },
                )
            return httpx.Response(404)

        return httpx.MockTransport(handler)


def _oidc_settings(**overrides: Any) -> Settings:
    defaults: dict[str, Any] = {
        "env": "test",
        "app_base_url": "http://127.0.0.1:8000",
        "session_secret": "Test_Session_Hmac_Aead_Key_32_Bytes_Minimum_01!",
        "csrf_secret": "Test_Csrf_Hmac_Key_32_Bytes_Minimum_Value_01!",
        "session_cookie_secure": False,
        "oidc_enabled": True,
        "oidc_allow_http_dev": True,
        "oidc_issuer": "https://idp.jyxia.local/realms/test",
        "oidc_client_id": "jyxia-test-client",
        "oidc_client_secret": "jyxia-test-client-secret-value-1234",
        "oidc_redirect_uri": "http://127.0.0.1:8000/api/v1/auth/callback",
        "oidc_post_logout_redirect_uri": "http://127.0.0.1:8000/",
        "oidc_mfa_required": True,
        "oidc_allowed_acr": ("urn:jyxia:loa:mfa",),
        "oidc_allowed_amr": ("otp", "totp", "hwk", "fido", "webauthn", "mfa"),
        "oidc_max_auth_age_seconds": 3600,
        "oidc_clock_skew_seconds": 60,
        "oidc_jwks_cache_ttl_seconds": 300,
        "oidc_jwks_refresh_cooldown_seconds": 15,
    }
    defaults.update(overrides)
    return Settings(**defaults)


def _sign_id_token(
    priv_key: Any,
    *,
    alg: str,
    kid: str,
    claims: dict[str, Any],
    headers: dict[str, Any] | None = None,
) -> str:
    hdrs = {"kid": kid, **(headers or {})}
    return jwt.encode(claims, priv_key, algorithm=alg, headers=hdrs)


def _base_claims(
    *,
    issuer: str = "https://idp.jyxia.local/realms/test",
    aud: str | list[str] = "jyxia-test-client",
    sub: str = "idp-sub-1",
    nonce: str = "raw-nonce-xyz",
    acr: str | None = "urn:jyxia:loa:mfa",
    amr: list[str] | None = None,
    auth_time: int | None = None,
) -> dict[str, Any]:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    claims: dict[str, Any] = {
        "iss": issuer,
        "sub": sub,
        "aud": aud,
        "nonce": nonce,
        "iat": now_ts - 5,
        "nbf": now_ts - 5,
        "exp": now_ts + 300,
        "auth_time": auth_time if auth_time is not None else now_ts - 10,
        "email": "admin@jyxia.local",
        "email_verified": True,
        "name": "Usuario Institucional Alpha",
    }
    if acr is not None:
        claims["acr"] = acr
    if amr is not None:
        claims["amr"] = amr
    else:
        claims["amr"] = ["pwd", "otp"]
    return claims
