"""Cryptographic primitives for opaque session tokens, CSRF verification, PKCE and AEAD."""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoEnvelopeError(ValueError):
    """Raised when encrypted ephemeral state cannot be decrypted or verified."""


def generate_opaque_token(nbytes: int = 32) -> str:
    """Generate URL-safe cryptographically random secret token."""
    return secrets.token_urlsafe(nbytes)


def hmac_token_digest(raw_token: str, *, secret: str, context: str) -> str:
    """Compute keyed HMAC-SHA256 hex digest (64 chars) so DB leaks cannot reverse tokens."""
    mac = hmac.new(
        f"{context}:{secret}".encode("utf-8"),
        raw_token.encode("utf-8"),
        hashlib.sha256,
    )
    return mac.hexdigest()


def constant_time_compare(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def compute_pkce_s256(code_verifier: str) -> str:
    """Compute RFC 7636 S256 code_challenge from high-entropy code_verifier."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _derive_aead_key(secret: str) -> bytes:
    return hashlib.sha256(f"jyxia:pkce-aead:{secret}".encode("utf-8")).digest()


def encrypt_pkce_verifier(code_verifier: str, *, secret: str, aad: str | None = None) -> str:
    """Encrypt PKCE code_verifier at rest in oidc_auth_states using AES-256-GCM."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(_derive_aead_key(secret))
    aad_bytes = f"jyxia:oidc:pkce:{aad}".encode("utf-8") if aad else b"jyxia:oidc:pkce"
    ct = aesgcm.encrypt(nonce, code_verifier.encode("ascii"), aad_bytes)
    return base64.urlsafe_b64encode(nonce + ct).decode("ascii")


def decrypt_pkce_verifier(token_blob: str, *, secret: str, aad: str | None = None) -> str:
    """Decrypt AEAD-protected PKCE code_verifier."""
    try:
        raw = base64.urlsafe_b64decode(token_blob.encode("ascii"))
        if len(raw) < 28:
            raise CryptoEnvelopeError("Corrupted PKCE verifier envelope.")
        nonce, ct = raw[:12], raw[12:]
        aad_bytes = f"jyxia:oidc:pkce:{aad}".encode("utf-8") if aad else b"jyxia:oidc:pkce"
        plain = AESGCM(_derive_aead_key(secret)).decrypt(nonce, ct, aad_bytes)
        return plain.decode("ascii")
    except (ValueError, InvalidTag) as exc:
        raise CryptoEnvelopeError("Unable to decrypt PKCE verifier.") from exc
