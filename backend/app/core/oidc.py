"""Provider-agnostic OpenID Connect (OIDC) discovery, JWKS caching, PKCE & MFA validation.

Uses PyJWT + cryptography for signature/claims verification and httpx for bounded
discovery, JWKS fetching and server-to-server authorization code exchange.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
import ipaddress
import logging
import socket
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol
from urllib.parse import urlencode, urlsplit

import httpx
import jwt
from jwt import PyJWK

from app.core.config import Settings
from app.core.logging import LOGGER_NAME, build_safe_log_extra
from app.core.session_crypto import compute_pkce_s256, constant_time_compare, hmac_token_digest

logger = logging.getLogger(LOGGER_NAME)


class OidcNotConfiguredError(RuntimeError):
    """Raised when OIDC endpoints are invoked while OIDC is disabled or incomplete."""


class OidcProviderUnavailableError(RuntimeError):
    """Raised when discovery, JWKS endpoint or token endpoint fails/times out."""

    def __init__(self, message: str, *, reason_code: str = "oidc_provider_unavailable") -> None:
        super().__init__(message)
        self.reason_code = reason_code


class OidcAuthenticationError(PermissionError):
    """Raised when OIDC tokens, state, nonce, signature or MFA verification fail closed."""

    def __init__(self, message: str, *, reason_code: str = "oidc_authentication_failed") -> None:
        super().__init__(message)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class OidcProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None = None


@dataclass(frozen=True, slots=True)
class VerifiedOidcIdentity:
    issuer: str
    subject: str
    email: str | None
    email_verified: bool
    name: str | None
    acr: str | None
    amr: tuple[str, ...]
    auth_time: datetime
    token_iat: datetime


class OidcProviderAdapter(Protocol):
    """Provider-agnostic boundary isolating application auth from specific IdP vendors."""

    def is_configured(self) -> bool:
        ...

    def configured_issuer(self) -> str:
        ...

    def build_authorization_url(
        self, *, state: str, nonce: str, code_verifier: str
    ) -> str:
        ...

    def exchange_authorization_code(
        self, *, code: str, code_verifier: str
    ) -> dict[str, Any]:
        ...

    def verify_id_token(
        self, raw_id_token: str, *, expected_nonce_hash: str, nonce_secret: str
    ) -> VerifiedOidcIdentity:
        ...

    def build_logout_url(self) -> str | None:
        ...


class _JwksKeyCache:
    """Thread-safe bounded JWKS cache with cooldown preventing refresh DoS."""

    def __init__(self, *, ttl_seconds: int, cooldown_seconds: int) -> None:
        self._ttl = ttl_seconds
        self._cooldown = cooldown_seconds
        self._lock = threading.RLock()
        self._keys: dict[str, Any] = {}
        self._fetched_at: float = 0.0
        self._last_forced_refresh_at: float = 0.0

    def get_key(
        self,
        kid: str | None,
        *,
        fetcher: Any,
    ) -> Any:
        now = time.monotonic()
        with self._lock:
            is_expired = (now - self._fetched_at) > self._ttl or not self._keys
            if is_expired:
                self._refresh_locked(fetcher, forced=False, now=now)

            resolved = self._lookup_locked(kid)
            if resolved is not None:
                return resolved

            # Unknown kid: honor cooldown before hitting IdP JWKS again
            if (now - self._last_forced_refresh_at) >= self._cooldown:
                self._refresh_locked(fetcher, forced=True, now=now)
                resolved = self._lookup_locked(kid)
                if resolved is not None:
                    return resolved

        raise OidcAuthenticationError("Token signing key (kid) is unknown or untrusted.")

    def _lookup_locked(self, kid: str | None) -> Any | None:
        if kid:
            return self._keys.get(kid)
        if len(self._keys) == 1:
            return next(iter(self._keys.values()))
        return None

    def _refresh_locked(self, fetcher: Any, *, forced: bool, now: float) -> None:
        jwks_doc = fetcher()
        parsed: dict[str, Any] = {}
        raw_keys = jwks_doc.get("keys")
        if not isinstance(raw_keys, list) or not raw_keys:
            raise OidcProviderUnavailableError("Provider JWKS response contained no signing keys.")
        for entry in raw_keys:
            if not isinstance(entry, dict):
                continue
            use = entry.get("use")
            if use is not None and use != "sig":
                continue
            entry_kid = entry.get("kid") or f"_unnamed_{len(parsed)}"
            try:
                parsed[str(entry_kid)] = PyJWK.from_dict(entry).key
            except Exception:
                continue
        if not parsed:
            raise OidcProviderUnavailableError("Provider JWKS contained no usable signature keys.")
        self._keys = parsed
        self._fetched_at = now
        if forced:
            self._last_forced_refresh_at = now


_DEV_LOOPBACK_HOSTS: frozenset[str] = frozenset({"127.0.0.1", "localhost", "::1", "keycloak"})


def _is_forbidden_ip_address(raw_ip: str) -> bool:
    cleaned = raw_ip.strip().strip("[]")
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return True
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return bool(
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or ip_obj.is_reserved
        or not ip_obj.is_global
    )


def _is_loopback_ip_address(raw_ip: str) -> bool:
    cleaned = raw_ip.strip().strip("[]")
    if "%" in cleaned:
        cleaned = cleaned.split("%", 1)[0]
    try:
        ip_obj = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return bool(ip_obj.is_loopback)


class StandardOidcProviderAdapter:
    """Standards-compliant OIDC adapter using trusted discovery, JWKS, PKCE & strict MFA."""

    def __init__(
        self,
        settings: Settings,
        *,
        transport: httpx.BaseTransport | None = None,
        dns_resolver: Callable[[str, int], Sequence[str]] | None = None,
    ) -> None:
        self._settings = settings
        self._transport = transport
        self._dns_resolver = dns_resolver
        self._metadata_lock = threading.RLock()
        self._metadata: OidcProviderMetadata | None = None
        self._metadata_fetched_at: float = 0.0
        self._pinned_host_ips: dict[tuple[str, int], frozenset[str]] = {}
        self._jwks_cache = _JwksKeyCache(
            ttl_seconds=settings.oidc_jwks_cache_ttl_seconds,
            cooldown_seconds=settings.oidc_jwks_refresh_cooldown_seconds,
        )

    def is_configured(self) -> bool:
        return bool(
            self._settings.oidc_enabled
            and self._settings.oidc_issuer
            and self._settings.oidc_client_id
            and self._settings.oidc_redirect_uri
        )

    def configured_issuer(self) -> str:
        if not self.is_configured():
            raise OidcNotConfiguredError("OIDC authentication is not configured.")
        return self._settings.oidc_issuer or ""

    def close(self) -> None:
        return None

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise OidcNotConfiguredError("OIDC authentication is not configured.")

    def _new_client(self) -> httpx.Client:
        return httpx.Client(
            timeout=self._settings.oidc_http_timeout_seconds,
            follow_redirects=False,
            transport=self._transport,
        )

    def _is_dev_loopback_allowed(self, hostname: str) -> bool:
        return bool(
            self._settings.oidc_allow_http_dev
            and self._settings.env in {"development", "test"}
            and hostname.lower().strip("[]") in _DEV_LOOPBACK_HOSTS
        )

    def _extract_canonical_origin(self, raw_url: str, *, field_name: str) -> tuple[str, str, int]:
        if not raw_url or any(ch.isspace() or ord(ch) < 32 for ch in raw_url):
            raise OidcAuthenticationError(f"Malformed URL for {field_name}.")
        try:
            parsed = urlsplit(raw_url)
        except ValueError as exc:
            raise OidcAuthenticationError(f"Malformed URL for {field_name}.") from exc

        scheme = (parsed.scheme or "").lower()
        if scheme not in {"http", "https"} or not parsed.netloc:
            raise OidcAuthenticationError(f"Refusing untrusted URL scheme for {field_name}.")
        if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
            raise OidcAuthenticationError(f"URL userinfo is prohibited in {field_name}.")
        if parsed.fragment:
            raise OidcAuthenticationError(f"URL fragment is prohibited in {field_name}.")
        hostname = (parsed.hostname or "").strip().lower().strip("[]")
        if not hostname or ".." in hostname:
            raise OidcAuthenticationError(f"Missing or invalid hostname in {field_name}.")
        try:
            port = parsed.port or (443 if scheme == "https" else 80)
        except ValueError as exc:
            raise OidcAuthenticationError(f"Invalid port in {field_name}.") from exc
        if port <= 0 or port > 65535:
            raise OidcAuthenticationError(f"Out-of-range port in {field_name}.")
        return scheme, hostname, port

    def _verify_and_resolve_host_ips(self, hostname: str, port: int, *, field_name: str) -> None:
        dev_loopback_ok = self._is_dev_loopback_allowed(hostname)

        # 1. Check literal IPv4 / IPv6 hostnames immediately
        try:
            ipaddress.ip_address(hostname)
            is_ip_literal = True
        except ValueError:
            is_ip_literal = False

        if is_ip_literal:
            if dev_loopback_ok and _is_loopback_ip_address(hostname):
                return
            if _is_forbidden_ip_address(hostname):
                raise OidcAuthenticationError(
                    f"Refusing non-global or private IP literal for {field_name}."
                )
            return

        if hostname in _DEV_LOOPBACK_HOSTS or hostname.endswith(".localhost"):
            if not dev_loopback_ok:
                raise OidcAuthenticationError(
                    f"Refusing loopback/local hostname for {field_name}."
                )
            return

        # 2. Resolve DNS records when custom resolver is provided or real network transport is active
        if self._dns_resolver is None and self._transport is not None:
            return

        try:
            if self._dns_resolver is not None:
                resolved_ips = tuple(str(ip).strip() for ip in self._dns_resolver(hostname, port))
            else:
                addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
                resolved_ips = tuple(
                    str(item[4][0]).strip() for item in addr_info if item and len(item) >= 5 and item[4]
                )
        except OSError as exc:
            raise OidcProviderUnavailableError(
                f"DNS resolution failed for {field_name}."
            ) from exc

        if not resolved_ips:
            raise OidcAuthenticationError(f"DNS resolution returned no addresses for {field_name}.")

        normalized_ips: set[str] = set()
        for ip_str in resolved_ips:
            if _is_forbidden_ip_address(ip_str):
                raise OidcAuthenticationError(
                    f"Refusing {field_name}: hostname resolved to private or non-global IP."
                )
            normalized_ips.add(ip_str)

        host_key = (hostname, port)
        with self._metadata_lock:
            previous_ips = self._pinned_host_ips.get(host_key)
            if previous_ips is not None and not (previous_ips & normalized_ips):
                raise OidcAuthenticationError(
                    f"Refusing {field_name}: suspicious DNS rebinding address change detected."
                )
            self._pinned_host_ips[host_key] = frozenset(normalized_ips)

    def _validate_provider_url(
        self,
        raw_url: str,
        *,
        field_name: str,
        require_issuer_origin: bool = False,
    ) -> str:
        scheme, hostname, port = self._extract_canonical_origin(raw_url, field_name=field_name)
        if scheme == "http":
            if not self._is_dev_loopback_allowed(hostname):
                raise OidcAuthenticationError(f"Refusing untrusted HTTP scheme for {field_name}.")
        elif scheme != "https":
            raise OidcAuthenticationError(f"Refusing untrusted URL scheme for {field_name}.")

        if require_issuer_origin and self._settings.oidc_issuer:
            iss_origin = self._extract_canonical_origin(
                self._settings.oidc_issuer, field_name="oidc_issuer"
            )
            if (scheme, hostname, port) != iss_origin:
                raise OidcAuthenticationError(
                    f"Refusing {field_name}: endpoint origin diverges from configured OIDC issuer."
                )

        self._verify_and_resolve_host_ips(hostname, port, field_name=field_name)
        return raw_url

    def get_metadata(self) -> OidcProviderMetadata:
        self._require_configured()
        now = time.monotonic()
        with self._metadata_lock:
            if (
                self._metadata is not None
                and (now - self._metadata_fetched_at) <= self._settings.oidc_jwks_cache_ttl_seconds
            ):
                return self._metadata

            assert self._settings.oidc_issuer is not None
            self._validate_provider_url(self._settings.oidc_issuer, field_name="oidc_issuer")
            discovery_url = self._validate_provider_url(
                f"{self._settings.oidc_issuer}/.well-known/openid-configuration",
                field_name="oidc_discovery",
                require_issuer_origin=True,
            )
            try:
                with self._new_client() as client:
                    resp = client.get(discovery_url)
            except httpx.HTTPError as exc:
                logger.warning(
                    "OIDC discovery fetch failed.",
                    extra=build_safe_log_extra(error_type=type(exc).__name__),
                )
                raise OidcProviderUnavailableError("OIDC identity provider is unavailable.") from exc

            if 300 <= resp.status_code < 400:
                raise OidcAuthenticationError("OIDC discovery redirects are prohibited.")
            try:
                resp.raise_for_status()
                doc = resp.json()
            except (httpx.HTTPError, ValueError) as exc:
                logger.warning(
                    "OIDC discovery response invalid.",
                    extra=build_safe_log_extra(error_type=type(exc).__name__),
                )
                raise OidcProviderUnavailableError("OIDC identity provider is unavailable.") from exc

            if not isinstance(doc, dict):
                raise OidcAuthenticationError("Malformed OIDC discovery document.")

            discovered_issuer = str(doc.get("issuer") or "").rstrip("/")
            if discovered_issuer != self._settings.oidc_issuer:
                raise OidcAuthenticationError("OIDC discovery issuer mismatch against trusted config.")

            auth_ep = self._validate_provider_url(
                str(doc.get("authorization_endpoint") or ""),
                field_name="authorization_endpoint",
                require_issuer_origin=True,
            )
            token_ep = self._validate_provider_url(
                str(doc.get("token_endpoint") or ""),
                field_name="token_endpoint",
                require_issuer_origin=True,
            )
            jwks_uri = self._validate_provider_url(
                str(doc.get("jwks_uri") or ""),
                field_name="jwks_uri",
                require_issuer_origin=True,
            )
            end_session_raw = doc.get("end_session_endpoint")
            end_session = (
                self._validate_provider_url(
                    str(end_session_raw),
                    field_name="end_session_endpoint",
                    require_issuer_origin=True,
                )
                if end_session_raw
                else None
            )

            self._metadata = OidcProviderMetadata(
                issuer=discovered_issuer,
                authorization_endpoint=auth_ep,
                token_endpoint=token_ep,
                jwks_uri=jwks_uri,
                end_session_endpoint=end_session,
            )
            self._metadata_fetched_at = now
            return self._metadata

    def _fetch_jwks(self) -> dict[str, Any]:
        meta = self.get_metadata()
        self._validate_provider_url(
            meta.jwks_uri, field_name="jwks_uri", require_issuer_origin=True
        )
        try:
            with self._new_client() as client:
                resp = client.get(meta.jwks_uri)
        except httpx.HTTPError as exc:
            logger.warning(
                "OIDC JWKS fetch failed.",
                extra=build_safe_log_extra(error_type=type(exc).__name__),
            )
            raise OidcProviderUnavailableError("Unable to reach OIDC JWKS endpoint.") from exc
        if 300 <= resp.status_code < 400:
            raise OidcAuthenticationError("OIDC JWKS redirects are prohibited.")
        try:
            resp.raise_for_status()
            doc = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning(
                "OIDC JWKS response invalid.",
                extra=build_safe_log_extra(error_type=type(exc).__name__),
            )
            raise OidcProviderUnavailableError("Unable to reach OIDC JWKS endpoint.") from exc
        if not isinstance(doc, dict):
            raise OidcProviderUnavailableError("Malformed JWKS payload.")
        return doc

    def build_authorization_url(self, *, state: str, nonce: str, code_verifier: str) -> str:
        meta = self.get_metadata()
        params: dict[str, str] = {
            "client_id": self._settings.oidc_client_id or "",
            "response_type": "code",
            "scope": "openid profile email",
            "redirect_uri": self._settings.oidc_redirect_uri or "",
            "state": state,
            "nonce": nonce,
            "code_challenge": compute_pkce_s256(code_verifier),
            "code_challenge_method": "S256",
        }
        if self._settings.oidc_mfa_required and self._settings.oidc_allowed_acr:
            params["acr_values"] = self._settings.oidc_allowed_acr[0]
        return f"{meta.authorization_endpoint}?{urlencode(params)}"

    def exchange_authorization_code(self, *, code: str, code_verifier: str) -> dict[str, Any]:
        meta = self.get_metadata()
        self._validate_provider_url(
            meta.token_endpoint, field_name="token_endpoint", require_issuer_origin=True
        )
        form_data: dict[str, str] = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self._settings.oidc_redirect_uri or "",
            "client_id": self._settings.oidc_client_id or "",
            "code_verifier": code_verifier,
        }
        if self._settings.oidc_client_secret:
            form_data["client_secret"] = self._settings.oidc_client_secret

        try:
            with self._new_client() as client:
                resp = client.post(
                    meta.token_endpoint,
                    data=form_data,
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError as exc:
            logger.warning(
                "OIDC token exchange network failure.",
                extra=build_safe_log_extra(error_type=type(exc).__name__),
            )
            raise OidcProviderUnavailableError("OIDC token endpoint unreachable.") from exc

        if 300 <= resp.status_code < 400:
            raise OidcAuthenticationError("OIDC token endpoint redirects are prohibited.")
        if resp.status_code >= 500:
            raise OidcProviderUnavailableError("OIDC token endpoint returned upstream error.")
        if resp.status_code != 200:
            raise OidcAuthenticationError("Authorization code exchange rejected by identity provider.")

        try:
            payload = resp.json()
        except ValueError as exc:
            raise OidcAuthenticationError("Invalid JSON from OIDC token endpoint.") from exc
        if not isinstance(payload, dict) or not payload.get("id_token"):
            raise OidcAuthenticationError("OIDC token response did not contain an id_token.")
        return payload

    def verify_id_token(
        self,
        raw_id_token: str,
        *,
        expected_nonce_hash: str,
        nonce_secret: str,
    ) -> VerifiedOidcIdentity:
        self._require_configured()
        if not raw_id_token or raw_id_token.count(".") != 2:
            raise OidcAuthenticationError("Malformed OIDC ID token.")

        try:
            header = jwt.get_unverified_header(raw_id_token)
        except jwt.PyJWTError as exc:
            raise OidcAuthenticationError("Unable to parse ID token header.") from exc

        alg = header.get("alg")
        if not alg or alg == "none" or alg not in self._settings.oidc_allowed_algorithms:
            raise OidcAuthenticationError("Prohibited or missing JWT signing algorithm.")

        typ = str(header.get("typ") or "").lower()
        if typ in {"at+jwt", "application/at+jwt"}:
            raise OidcAuthenticationError("Access token cannot be used in place of an OIDC ID token.")

        signing_key = self._jwks_cache.get_key(
            header.get("kid"),
            fetcher=self._fetch_jwks,
        )

        expected_issuer = self._settings.oidc_issuer or ""
        expected_audience = self._settings.effective_oidc_audience()

        try:
            claims = jwt.decode(
                raw_id_token,
                signing_key,
                algorithms=list(self._settings.oidc_allowed_algorithms),
                issuer=expected_issuer,
                audience=expected_audience,
                leeway=self._settings.oidc_clock_skew_seconds,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": True,
                    "require": ["exp", "iat", "iss", "aud", "sub", "nonce"],
                },
            )
        except jwt.PyJWTError as exc:
            raise OidcAuthenticationError(f"ID token validation failed: {type(exc).__name__}") from exc

        # Reject Access Tokens mistakenly accepted as ID tokens via token_use / scope heuristics
        if claims.get("token_use") == "access":
            raise OidcAuthenticationError("Access token rejected by ID token verifier.")

        # OIDC Core 1.0 Section 3.1.3.7(4-5): verify azp when multiple audiences exist
        aud_claim = claims.get("aud")
        if isinstance(aud_claim, list) and len(aud_claim) > 1:
            azp = claims.get("azp")
            if azp != self._settings.oidc_client_id:
                raise OidcAuthenticationError("Token authorized party (azp) mismatch.")

        raw_nonce = claims.get("nonce")
        if not isinstance(raw_nonce, str) or not raw_nonce:
            raise OidcAuthenticationError("ID token missing valid nonce claim.")
        presented_nonce_hash = hmac_token_digest(
            raw_nonce, secret=nonce_secret, context="oidc_nonce"
        )
        if not constant_time_compare(presented_nonce_hash, expected_nonce_hash):
            raise OidcAuthenticationError("ID token nonce mismatch.")

        now_ts = int(datetime.now(timezone.utc).timestamp())
        skew = self._settings.oidc_clock_skew_seconds
        iat_val = int(claims["iat"])
        if iat_val > now_ts + skew:
            raise OidcAuthenticationError("ID token iat is too far in the future.")

        auth_time, acr_value, amr_tuple = self._verify_mfa_evidence(claims, now_ts=now_ts, skew=skew, fallback_iat=iat_val)

        return VerifiedOidcIdentity(
            issuer=str(claims["iss"]),
            subject=str(claims["sub"]),
            email=str(claims["email"]).strip().lower() if claims.get("email") else None,
            email_verified=bool(claims.get("email_verified", False)),
            name=str(claims["name"]).strip() if claims.get("name") else None,
            acr=acr_value,
            amr=amr_tuple,
            auth_time=auth_time,
            token_iat=datetime.fromtimestamp(iat_val, tz=timezone.utc),
        )

    def _verify_mfa_evidence(
        self,
        claims: dict[str, Any],
        *,
        now_ts: int,
        skew: int,
        fallback_iat: int,
    ) -> tuple[datetime, str | None, tuple[str, ...]]:
        acr_raw = claims.get("acr")
        acr_value = str(acr_raw).strip() if isinstance(acr_raw, str) and acr_raw.strip() else None

        amr_raw = claims.get("amr")
        amr_tuple: tuple[str, ...] = ()
        if isinstance(amr_raw, list):
            amr_tuple = tuple(
                str(item).strip().lower()
                for item in amr_raw
                if isinstance(item, str) and item.strip()
            )
        elif amr_raw is not None:
            raise OidcAuthenticationError("Malformed amr claim type.")

        auth_time_raw = claims.get("auth_time")
        if self._settings.oidc_mfa_required:
            if not isinstance(auth_time_raw, (int, float)) or isinstance(auth_time_raw, bool):
                raise OidcAuthenticationError("MFA policy requires numeric auth_time claim.")
            auth_time_ts = int(auth_time_raw)
            if auth_time_ts > now_ts + skew:
                raise OidcAuthenticationError("Invalid future auth_time claim.")
            if (now_ts - auth_time_ts) > self._settings.oidc_max_auth_age_seconds:
                raise OidcAuthenticationError("Authentication is older than permitted max_auth_age.")

            # Check ACR and AMR second-factor verification
            allowed_acr = set(self._settings.oidc_allowed_acr)
            allowed_amr = set(self._settings.oidc_allowed_amr)

            amr_set = set(amr_tuple)
            if not amr_set:
                raise OidcAuthenticationError(
                    "MFA policy requires non-empty amr claim proving second-factor authentication."
                )
            if amr_set <= {"pwd", "password"}:
                raise OidcAuthenticationError("Password-only authentication does not satisfy MFA.")

            has_second_factor_amr = bool(amr_set & allowed_amr)
            if not has_second_factor_amr:
                raise OidcAuthenticationError(
                    "Token amr lacks an authorized MFA second-factor method."
                )

            acr_ok = bool(acr_value and acr_value in allowed_acr) if allowed_acr else False
            if self._settings.oidc_require_both_acr_and_amr or allowed_acr:
                if not acr_ok:
                    raise OidcAuthenticationError(
                        "Token lacks required MFA acr assurance level."
                    )
        else:
            auth_time_ts = int(auth_time_raw) if isinstance(auth_time_raw, (int, float)) else fallback_iat

        return datetime.fromtimestamp(auth_time_ts, tz=timezone.utc), acr_value, amr_tuple

    def build_logout_url(self) -> str | None:
        if not self.is_configured():
            return None
        try:
            meta = self.get_metadata()
        except OidcProviderUnavailableError:
            return None
        if not meta.end_session_endpoint:
            return None
        params: dict[str, str] = {"client_id": self._settings.oidc_client_id or ""}
        if self._settings.oidc_post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = self._settings.oidc_post_logout_redirect_uri
        return f"{meta.end_session_endpoint}?{urlencode(params)}"
