"""Server-side OIDC BFF login, session, CSRF/Origin, and multi-tenant authorization service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from sqlalchemy.orm import Session, sessionmaker

from app.core.config import Settings, load_settings
from app.core.constants import (
    ExternalIdentityStatus,
    OrganizationRole,
    SecurityAuditOutcome,
)
from app.core.oidc import (
    OidcAuthenticationError,
    OidcNotConfiguredError,
    OidcProviderAdapter,
    OidcProviderUnavailableError,
)
from app.core.rbac import (
    AuthenticatedSessionPrincipal,
    AuthenticationRequiredError,
    AuthorizationDeniedError,
    AuthorizedTenantPrincipal,
    RbacPermission,
    permissions_for_role,
    require_tenant_permission,
)
from app.core.session_crypto import (
    CryptoEnvelopeError,
    constant_time_compare,
    decrypt_pkce_verifier,
    encrypt_pkce_verifier,
    generate_opaque_token,
    hmac_token_digest,
)
from app.db.base import utc_now
from app.db.session import apply_pg_rls_context
from app.models.entities import Organization
from app.repositories.identity import (
    IdentityAndSessionRepository,
    SecurityAuditRepository,
)
from app.repositories.institutional import AuditEventRepository
from app.schemas.tenant import TenantContext


@dataclass(frozen=True, slots=True)
class LoginInitiationResult:
    authorization_url: str
    tx_cookie_value: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class CallbackSuccessResult:
    session_token: str
    csrf_token: str
    redirect_path: str
    principal: AuthenticatedSessionPrincipal


@dataclass(frozen=True, slots=True)
class AuthorizedMembershipContext:
    principal: AuthorizedTenantPrincipal
    organization: Organization


@dataclass(frozen=True, slots=True)
class OrganizationSelectionResult:
    organization: Organization
    role: OrganizationRole
    permissions: list[str]
    session_token: str
    csrf_token: str
    session_id: str


def _extract_strict_origin(
    raw_url: str | None,
    *,
    allow_path_and_query: bool = False,
) -> tuple[str, str, int] | None:
    """Parse and normalize a strict (scheme, hostname, port) origin without userinfo or wildcards."""
    if raw_url is None:
        return None
    cleaned = raw_url.strip()
    if not cleaned or cleaned.lower() == "null" or "*" in cleaned:
        return None
    if any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in cleaned):
        return None
    try:
        parsed = urlsplit(cleaned)
    except ValueError:
        return None

    scheme = (parsed.scheme or "").lower()
    if scheme not in {"http", "https"} or not parsed.netloc:
        return None
    if parsed.username is not None or parsed.password is not None or "@" in parsed.netloc:
        return None
    if parsed.fragment:
        return None
    if not allow_path_and_query:
        if parsed.path not in {"", "/"} or parsed.query:
            return None

    hostname = (parsed.hostname or "").strip().lower().strip("[]")
    if not hostname or ".." in hostname:
        return None
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        return None
    if port <= 0 or port > 65535:
        return None
    return scheme, hostname, port


def sanitize_next_path(next_path: str | None) -> str | None:
    """Permit strictly relative application paths without scheme or protocol-relative redirects."""
    if next_path is None:
        return None
    cleaned = next_path.strip()
    if not cleaned:
        return None
    if (
        len(cleaned) > 500
        or not cleaned.startswith("/")
        or cleaned.startswith("//")
        or "\\" in cleaned
        or "://" in cleaned
        or any(ord(ch) < 32 or ord(ch) == 127 for ch in cleaned)
    ):
        raise AuthenticationRequiredError("Invalid relative redirect path.")
    return cleaned


def verify_csrf_and_origin(
    *,
    settings: Settings,
    session_factory: sessionmaker[Session] | None,
    principal: AuthenticatedSessionPrincipal,
    csrf_cookie: str | None,
    csrf_header: str | None,
    origin_header: str | None,
    referer_header: str | None,
    correlation_id: str | None = None,
) -> None:
    """Enforce trusted Origin/Referer and server-bound double-submit CSRF verification."""
    allowed_origins: set[tuple[str, str, int]] = set()
    app_origin = _extract_strict_origin(settings.app_base_url, allow_path_and_query=False)
    if app_origin is not None:
        allowed_origins.add(app_origin)
    for cors_origin in settings.cors_allowed_origins:
        parsed_cors = _extract_strict_origin(cors_origin, allow_path_and_query=False)
        if parsed_cors is not None:
            allowed_origins.add(parsed_cors)

    # When Origin header is present, validate it directly and NEVER fall back to Referer.
    if origin_header is not None:
        candidate_origin = _extract_strict_origin(origin_header, allow_path_and_query=False)
        reason_code = "untrusted_or_invalid_origin"
    elif referer_header is not None:
        candidate_origin = _extract_strict_origin(referer_header, allow_path_and_query=True)
        reason_code = "untrusted_or_invalid_referer"
    else:
        candidate_origin = None
        reason_code = "missing_origin_and_referer"

    if candidate_origin is None or candidate_origin not in allowed_origins:
        if session_factory is not None:
            SecurityAuditRepository.append_event_atomic(
                session_factory,
                event_type="CSRF_ORIGIN_DENIED",
                outcome=SecurityAuditOutcome.DENIED,
                reason_code=reason_code,
                payload_json={"had_origin": origin_header is not None, "had_referer": referer_header is not None},
                user_id=principal.user_id,
                organization_id=principal.selected_organization_id,
                session_id=principal.session_id,
                correlation_id=correlation_id,
            )
        raise AuthorizationDeniedError("Untrusted or missing request Origin.")

    if not csrf_cookie or not csrf_header or not constant_time_compare(csrf_cookie, csrf_header):
        if session_factory is not None:
            SecurityAuditRepository.append_event_atomic(
                session_factory,
                event_type="CSRF_TOKEN_DENIED",
                outcome=SecurityAuditOutcome.DENIED,
                reason_code="csrf_header_cookie_mismatch",
                payload_json={"had_cookie": bool(csrf_cookie), "had_header": bool(csrf_header)},
                user_id=principal.user_id,
                organization_id=principal.selected_organization_id,
                session_id=principal.session_id,
                correlation_id=correlation_id,
            )
        raise AuthorizationDeniedError("Missing or mismatched CSRF token.")

    presented_hash = hmac_token_digest(
        csrf_header, secret=settings.csrf_secret, context="csrf_token"
    )
    if not principal.csrf_token_hash or not constant_time_compare(
        presented_hash, principal.csrf_token_hash
    ):
        if session_factory is not None:
            SecurityAuditRepository.append_event_atomic(
                session_factory,
                event_type="CSRF_TOKEN_DENIED",
                outcome=SecurityAuditOutcome.DENIED,
                reason_code="csrf_session_digest_mismatch",
                payload_json={"status": "digest_mismatch"},
                user_id=principal.user_id,
                organization_id=principal.selected_organization_id,
                session_id=principal.session_id,
                correlation_id=correlation_id,
            )
        raise AuthorizationDeniedError("Invalid session CSRF token.")


def start_oidc_login(
    session_factory: sessionmaker[Session],
    *,
    settings: Settings,
    oidc_adapter: OidcProviderAdapter,
    next_path: str | None = None,
    correlation_id: str | None = None,
) -> LoginInitiationResult:
    """Create PKCE S256 transaction state and return OIDC provider authorization redirect URL."""
    if not settings.oidc_enabled or not oidc_adapter.is_configured():
        raise OidcNotConfiguredError("Institutional OIDC authentication is not configured.")

    safe_next = sanitize_next_path(next_path)
    state = generate_opaque_token()
    nonce = generate_opaque_token()
    code_verifier = generate_opaque_token(48)

    state_hash = hmac_token_digest(state, secret=settings.session_secret, context="oidc_state")
    nonce_hash = hmac_token_digest(nonce, secret=settings.session_secret, context="oidc_nonce")
    tx_cookie_value = hmac_token_digest(
        state, secret=settings.csrf_secret, context="oidc_tx_cookie"
    )
    verifier_ciphertext = encrypt_pkce_verifier(
        code_verifier,
        secret=settings.session_secret,
        aad=state_hash,
    )

    now = utc_now().astimezone(timezone.utc)
    expires_at = now + timedelta(seconds=600)
    issuer = oidc_adapter.configured_issuer()
    redirect_uri = settings.oidc_redirect_uri or ""

    authorization_url = oidc_adapter.build_authorization_url(
        state=state,
        nonce=nonce,
        code_verifier=code_verifier,
    )

    session = session_factory()
    try:
        IdentityAndSessionRepository.create_oidc_auth_state(
            session,
            state_hash=state_hash,
            nonce_hash=nonce_hash,
            code_verifier_ciphertext=verifier_ciphertext,
            issuer=issuer,
            redirect_uri=redirect_uri,
            next_path=safe_next,
            expires_at=expires_at,
        )
        SecurityAuditRepository.append_event(
            session,
            event_type="OIDC_LOGIN_STARTED",
            outcome=SecurityAuditOutcome.SUCCESS,
            reason_code="pkce_state_issued",
            payload_json={"has_next_path": safe_next is not None},
            issuer=issuer,
            correlation_id=correlation_id,
            created_at=now,
        )
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    return LoginInitiationResult(
        authorization_url=authorization_url,
        tx_cookie_value=tx_cookie_value,
        expires_at=expires_at,
    )


def _record_failed_callback(
    session_factory: sessionmaker[Session],
    *,
    event_type: str,
    outcome: SecurityAuditOutcome,
    reason_code: str,
    issuer: str | None = None,
    subject: str | None = None,
    user_id: str | None = None,
    correlation_id: str | None = None,
) -> None:
    SecurityAuditRepository.append_event_atomic(
        session_factory,
        event_type=event_type,
        outcome=outcome,
        reason_code=reason_code,
        payload_json={"flow": "oidc_callback"},
        user_id=user_id,
        issuer=issuer,
        subject=subject,
        correlation_id=correlation_id,
    )


def complete_oidc_callback(
    session_factory: sessionmaker[Session],
    *,
    settings: Settings,
    oidc_adapter: OidcProviderAdapter,
    code: str | None,
    state: str | None,
    tx_cookie_value: str | None,
    idp_error: str | None = None,
    correlation_id: str | None = None,
) -> CallbackSuccessResult:
    """Complete OIDC PKCE callback, enforce MFA, match (issuer, subject), and issue BFF session."""
    if not settings.oidc_enabled or not oidc_adapter.is_configured():
        raise OidcNotConfiguredError("Institutional OIDC authentication is not configured.")

    if idp_error:
        _record_failed_callback(
            session_factory,
            event_type="OIDC_CALLBACK_FAILED",
            outcome=SecurityAuditOutcome.FAILURE,
            reason_code="idp_returned_error",
            issuer=oidc_adapter.configured_issuer(),
            correlation_id=correlation_id,
        )
        raise AuthenticationRequiredError("Identity provider denied authentication.")

    if not code or not state or not tx_cookie_value:
        _record_failed_callback(
            session_factory,
            event_type="OIDC_CALLBACK_FAILED",
            outcome=SecurityAuditOutcome.FAILURE,
            reason_code="missing_callback_parameters",
            issuer=oidc_adapter.configured_issuer(),
            correlation_id=correlation_id,
        )
        raise AuthenticationRequiredError("Missing required OIDC callback parameters.")

    expected_tx = hmac_token_digest(
        state, secret=settings.csrf_secret, context="oidc_tx_cookie"
    )
    if not constant_time_compare(tx_cookie_value, expected_tx):
        _record_failed_callback(
            session_factory,
            event_type="OIDC_CALLBACK_FAILED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code="oidc_tx_cookie_mismatch",
            issuer=oidc_adapter.configured_issuer(),
            correlation_id=correlation_id,
        )
        raise AuthenticationRequiredError("Invalid OIDC login transaction binding.")

    now = utc_now().astimezone(timezone.utc)
    state_hash = hmac_token_digest(state, secret=settings.session_secret, context="oidc_state")

    session = session_factory()
    try:
        auth_state = IdentityAndSessionRepository.consume_oidc_auth_state_atomic(
            session, state_hash=state_hash, now=now
        )
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()

    if auth_state is None:
        _record_failed_callback(
            session_factory,
            event_type="OIDC_CALLBACK_FAILED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code="oidc_state_invalid_expired_or_replayed",
            issuer=oidc_adapter.configured_issuer(),
            correlation_id=correlation_id,
        )
        raise AuthenticationRequiredError("OIDC state is invalid, expired, or already used.")

    if auth_state.issuer != oidc_adapter.configured_issuer():
        _record_failed_callback(
            session_factory,
            event_type="OIDC_CALLBACK_FAILED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code="oidc_state_issuer_mismatch",
            issuer=oidc_adapter.configured_issuer(),
            correlation_id=correlation_id,
        )
        raise AuthenticationRequiredError("OIDC issuer mismatch.")

    try:
        code_verifier = decrypt_pkce_verifier(
            auth_state.code_verifier_ciphertext,
            secret=settings.session_secret,
            aad=state_hash,
        )
    except CryptoEnvelopeError as exc:
        _record_failed_callback(
            session_factory,
            event_type="OIDC_CALLBACK_FAILED",
            outcome=SecurityAuditOutcome.FAILURE,
            reason_code="pkce_verifier_decrypt_failed",
            issuer=auth_state.issuer,
            correlation_id=correlation_id,
        )
        raise AuthenticationRequiredError("Failed to validate OIDC transaction verifier.") from exc

    try:
        token_payload = oidc_adapter.exchange_authorization_code(
            code=code,
            code_verifier=code_verifier,
        )
        verified = oidc_adapter.verify_id_token(
            str(token_payload["id_token"]),
            expected_nonce_hash=auth_state.nonce_hash,
            nonce_secret=settings.session_secret,
        )
    except OidcProviderUnavailableError as exc:
        _record_failed_callback(
            session_factory,
            event_type="OIDC_PROVIDER_UNAVAILABLE",
            outcome=SecurityAuditOutcome.FAILURE,
            reason_code=exc.reason_code,
            issuer=auth_state.issuer,
            correlation_id=correlation_id,
        )
        raise
    except OidcAuthenticationError as exc:
        _record_failed_callback(
            session_factory,
            event_type="OIDC_TOKEN_OR_MFA_REJECTED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code=exc.reason_code,
            issuer=auth_state.issuer,
            correlation_id=correlation_id,
        )
        raise AuthenticationRequiredError("OIDC token or MFA policy rejected.") from exc

    # Resolve federated identity strictly by (issuer, subject).
    session = session_factory()
    try:
        resolved = IdentityAndSessionRepository.get_external_identity_by_issuer_subject(
            session, issuer=verified.issuer, subject=verified.subject
        )
        if resolved is None:
            SecurityAuditRepository.append_event(
                session,
                event_type="AUTH_IDENTITY_UNBOUND",
                outcome=SecurityAuditOutcome.DENIED,
                reason_code="external_identity_not_provisioned",
                payload_json={"mfa_acr": verified.acr},
                issuer=verified.issuer,
                subject=verified.subject,
                correlation_id=correlation_id,
                created_at=now,
            )
            session.commit()
            raise AuthorizationDeniedError(
                "Federated identity is not bound to an authorized institutional account."
            )

        external_identity, user = resolved
        if external_identity.status != ExternalIdentityStatus.ACTIVE.value or not user.is_active:
            SecurityAuditRepository.append_event(
                session,
                event_type="AUTH_IDENTITY_DISABLED",
                outcome=SecurityAuditOutcome.DENIED,
                reason_code="user_or_identity_inactive",
                payload_json={"identity_status": external_identity.status, "user_active": user.is_active},
                user_id=user.id,
                issuer=verified.issuer,
                subject=verified.subject,
                correlation_id=correlation_id,
                created_at=now,
            )
            session.commit()
            raise AuthorizationDeniedError("Institutional user or federated identity is inactive.")

        memberships = IdentityAndSessionRepository.list_user_active_memberships(
            session, user_id=user.id
        )
        if not memberships:
            SecurityAuditRepository.append_event(
                session,
                event_type="AUTH_NO_ACTIVE_MEMBERSHIP",
                outcome=SecurityAuditOutcome.DENIED,
                reason_code="no_active_organization_membership",
                payload_json={"mfa_acr": verified.acr},
                user_id=user.id,
                issuer=verified.issuer,
                subject=verified.subject,
                correlation_id=correlation_id,
                created_at=now,
            )
            session.commit()
            raise AuthorizationDeniedError(
                "User holds no active membership in an active organization."
            )

        active_org_id = memberships[0][0].organization_id if len(memberships) == 1 else None
        effective_acr = verified.acr or f"amr:{','.join(verified.amr)}"

        raw_session_token = generate_opaque_token(32)
        raw_csrf_token = generate_opaque_token(32)
        session_token_hash = hmac_token_digest(
            raw_session_token, secret=settings.session_secret, context="session_token"
        )
        csrf_token_hash = hmac_token_digest(
            raw_csrf_token, secret=settings.csrf_secret, context="csrf_token"
        )
        idle_expires_at = now + timedelta(seconds=settings.session_idle_timeout_seconds)
        absolute_expires_at = now + timedelta(seconds=settings.session_absolute_timeout_seconds)

        auth_session = IdentityAndSessionRepository.create_auth_session(
            session,
            user_id=user.id,
            external_identity_id=external_identity.id,
            active_organization_id=active_org_id,
            session_token_hash=session_token_hash,
            csrf_token_hash=csrf_token_hash,
            auth_method="oidc_pkce_mfa",
            acr=effective_acr,
            amr_json=list(verified.amr),
            mfa_verified_at=now,
            oidc_auth_time=verified.auth_time,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
            now=now,
        )
        IdentityAndSessionRepository.touch_external_identity_login(
            session, external_identity.id, authenticated_at=now
        )
        SecurityAuditRepository.append_event(
            session,
            event_type="AUTH_LOGIN_SUCCEEDED",
            outcome=SecurityAuditOutcome.SUCCESS,
            reason_code="oidc_mfa_session_issued",
            payload_json={
                "acr": effective_acr,
                "amr_count": len(verified.amr),
                "org_count": len(memberships),
            },
            user_id=user.id,
            organization_id=active_org_id,
            issuer=verified.issuer,
            subject=verified.subject,
            session_id=auth_session.id,
            correlation_id=correlation_id,
            created_at=now,
        )
        if active_org_id is not None:
            AuditEventRepository.append_event(
                session,
                TenantContext(
                    organization_id=active_org_id,
                    actor_user_id=user.id,
                    source="authenticated_request",
                ),
                event_type="AUTH_SESSION_ESTABLISHED",
                target_entity_type="auth_session",
                target_entity_id=auth_session.id,
                payload_json={"auth_method": "oidc_pkce_mfa", "acr": effective_acr},
                created_at=now,
            )
        session.commit()

        principal = AuthenticatedSessionPrincipal(
            session_id=auth_session.id,
            user_id=user.id,
            external_identity_id=external_identity.id,
            issuer=external_identity.issuer,
            subject=external_identity.subject,
            email=user.email,
            display_name=user.display_name,
            mfa_verified=True,
            mfa_verified_at=now,
            auth_time=_as_utc(verified.auth_time),
            acr=effective_acr,
            amr=verified.amr,
            selected_organization_id=active_org_id,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
            csrf_token_hash=csrf_token_hash,
        )
        return CallbackSuccessResult(
            session_token=raw_session_token,
            csrf_token=raw_csrf_token,
            redirect_path=auth_state.next_path or "/",
            principal=principal,
        )
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def authenticate_session_cookie(
    session: Session,
    *,
    settings: Settings,
    raw_session_token: str | None,
    correlation_id: str | None = None,
) -> AuthenticatedSessionPrincipal:
    """Validate opaque session cookie against server-side DB state, timeouts, and MFA."""
    if not raw_session_token or len(raw_session_token) < 20:
        raise AuthenticationRequiredError("Authentication session cookie is required.")

    token_hash = hmac_token_digest(
        raw_session_token, secret=settings.session_secret, context="session_token"
    )
    resolved = IdentityAndSessionRepository.get_session_with_identity(
        session, session_token_hash=token_hash
    )
    if resolved is None:
        raise AuthenticationRequiredError("Invalid or unknown session.")

    auth_session, user, external_identity = resolved
    now = utc_now().astimezone(timezone.utc)

    if auth_session.revoked_at is not None:
        raise AuthenticationRequiredError("Session has been revoked.")

    abs_exp = _as_utc(auth_session.absolute_expires_at)
    idle_exp = _as_utc(auth_session.idle_expires_at)
    if now >= abs_exp or now >= idle_exp:
        reason = "session_absolute_timeout" if now >= abs_exp else "session_idle_timeout"
        IdentityAndSessionRepository.revoke_session(
            session, session_id=auth_session.id, now=now, reason=reason
        )
        SecurityAuditRepository.append_event(
            session,
            event_type="AUTH_SESSION_EXPIRED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code=reason,
            payload_json={"session_expired": True},
            user_id=user.id,
            organization_id=auth_session.active_organization_id,
            session_id=auth_session.id,
            correlation_id=correlation_id,
            created_at=now,
        )
        session.commit()
        raise AuthenticationRequiredError("Session expired.")

    if not user.is_active or external_identity.status != ExternalIdentityStatus.ACTIVE.value:
        IdentityAndSessionRepository.revoke_session(
            session, session_id=auth_session.id, now=now, reason="identity_or_user_inactive"
        )
        SecurityAuditRepository.append_event(
            session,
            event_type="AUTH_SESSION_IDENTITY_REVOKED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code="identity_or_user_inactive",
            payload_json={"user_active": user.is_active, "identity_status": external_identity.status},
            user_id=user.id,
            organization_id=auth_session.active_organization_id,
            session_id=auth_session.id,
            correlation_id=correlation_id,
            created_at=now,
        )
        session.commit()
        raise AuthenticationRequiredError("Authenticated user or identity is no longer active.")

    if auth_session.mfa_verified_at is None:
        raise AuthenticationRequiredError("Session lacks verified MFA assurance.")

    new_idle = min(abs_exp, now + timedelta(seconds=settings.session_idle_timeout_seconds))
    IdentityAndSessionRepository.touch_auth_session(
        session, session_id=auth_session.id, now=now, new_idle_expires_at=new_idle
    )
    session.commit()

    return AuthenticatedSessionPrincipal(
        session_id=auth_session.id,
        user_id=user.id,
        external_identity_id=external_identity.id,
        issuer=external_identity.issuer,
        subject=external_identity.subject,
        email=user.email,
        display_name=user.display_name,
        mfa_verified=True,
        mfa_verified_at=_as_utc(auth_session.mfa_verified_at),
        auth_time=_as_utc(auth_session.oidc_auth_time),
        acr=auth_session.acr,
        amr=tuple(str(item) for item in auth_session.amr_json),
        selected_organization_id=auth_session.active_organization_id,
        idle_expires_at=new_idle,
        absolute_expires_at=abs_exp,
        csrf_token_hash=auth_session.csrf_token_hash,
    )


def select_active_organization(
    session: Session,
    *,
    principal: AuthenticatedSessionPrincipal,
    organization_id: str,
    settings: Settings | None = None,
    correlation_id: str | None = None,
) -> OrganizationSelectionResult:
    """Switch active session organization and rotate session/CSRF tokens upon verified DB membership."""
    resolved_settings = settings if settings is not None else load_settings(strict_database=False)
    now = utc_now().astimezone(timezone.utc)
    found = IdentityAndSessionRepository.get_active_membership_for_org(
        session, user_id=principal.user_id, organization_id=organization_id
    )
    if found is None:
        SecurityAuditRepository.append_event(
            session,
            event_type="ORG_SELECTION_DENIED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code="no_active_membership_for_selected_org",
            payload_json={"attempted_organization_id": organization_id},
            user_id=principal.user_id,
            organization_id=principal.selected_organization_id,
            session_id=principal.session_id,
            correlation_id=correlation_id,
            created_at=now,
        )
        session.commit()
        raise AuthorizationDeniedError("Caller lacks active membership in target organization.")

    membership, org = found
    role = OrganizationRole(membership.role)

    # Invalidate previous session and rotate both session and CSRF tokens for the new tenant context
    IdentityAndSessionRepository.revoke_session(
        session,
        session_id=principal.session_id,
        now=now,
        reason="rotated_on_organization_select",
    )

    new_raw_session_token = generate_opaque_token(32)
    new_raw_csrf_token = generate_opaque_token(32)
    new_session_token_hash = hmac_token_digest(
        new_raw_session_token,
        secret=resolved_settings.session_secret,
        context="session_token",
    )
    new_csrf_token_hash = hmac_token_digest(
        new_raw_csrf_token,
        secret=resolved_settings.csrf_secret,
        context="csrf_token",
    )
    abs_exp = (
        _as_utc(principal.absolute_expires_at)
        if principal.absolute_expires_at is not None
        else (now + timedelta(seconds=resolved_settings.session_absolute_timeout_seconds))
    )
    new_idle = min(
        abs_exp,
        now + timedelta(seconds=resolved_settings.session_idle_timeout_seconds),
    )

    rotated_session = IdentityAndSessionRepository.create_auth_session(
        session,
        user_id=principal.user_id,
        external_identity_id=principal.external_identity_id,
        active_organization_id=org.id,
        session_token_hash=new_session_token_hash,
        csrf_token_hash=new_csrf_token_hash,
        auth_method="oidc_pkce_mfa",
        acr=principal.acr or "urn:jyxia:loa:mfa",
        amr_json=list(principal.amr),
        mfa_verified_at=_as_utc(principal.mfa_verified_at),
        oidc_auth_time=_as_utc(principal.auth_time),
        idle_expires_at=new_idle,
        absolute_expires_at=abs_exp,
        now=now,
    )

    SecurityAuditRepository.append_event(
        session,
        event_type="ORG_CONTEXT_SELECTED",
        outcome=SecurityAuditOutcome.SUCCESS,
        reason_code="active_membership_verified_session_rotated",
        payload_json={
            "role": role.value,
            "previous_session_id": principal.session_id,
            "rotated": True,
        },
        user_id=principal.user_id,
        organization_id=org.id,
        session_id=rotated_session.id,
        correlation_id=correlation_id,
        created_at=now,
    )
    AuditEventRepository.append_event(
        session,
        TenantContext(
            organization_id=org.id,
            actor_user_id=principal.user_id,
            source="authenticated_request",
        ),
        event_type="ORGANIZATION_CONTEXT_SELECTED",
        target_entity_type="auth_session",
        target_entity_id=rotated_session.id,
        payload_json={
            "role": role.value,
            "previous_session_id": principal.session_id,
            "rotated": True,
        },
        created_at=now,
    )
    session.commit()
    perms = sorted(perm.value for perm in permissions_for_role(role))
    return OrganizationSelectionResult(
        organization=org,
        role=role,
        permissions=perms,
        session_token=new_raw_session_token,
        csrf_token=new_raw_csrf_token,
        session_id=rotated_session.id,
    )


def resolve_authorized_tenant_principal(
    session: Session,
    *,
    principal: AuthenticatedSessionPrincipal,
    organization_id: str,
    required_permission: RbacPermission,
    spoofed_org_header: str | None = None,
    correlation_id: str | None = None,
) -> AuthorizedMembershipContext:
    """Derive DB-verified multi-tenant authorization context and bind PostgreSQL RLS."""
    now = utc_now().astimezone(timezone.utc)
    if spoofed_org_header and spoofed_org_header.strip() != organization_id:
        SecurityAuditRepository.append_event(
            session,
            event_type="TENANT_HEADER_SPOOF_REJECTED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code="spoofed_organization_header_mismatch",
            payload_json={"path_org_matched": False},
            user_id=principal.user_id,
            organization_id=principal.selected_organization_id,
            session_id=principal.session_id,
            correlation_id=correlation_id,
            created_at=now,
        )
        session.commit()
        raise AuthorizationDeniedError("Conflicting organization header is prohibited.")

    if principal.selected_organization_id is None:
        SecurityAuditRepository.append_event(
            session,
            event_type="TENANT_ACCESS_DENIED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code="active_organization_not_selected",
            payload_json={"required_permission": required_permission.value},
            user_id=principal.user_id,
            organization_id=None,
            session_id=principal.session_id,
            correlation_id=correlation_id,
            created_at=now,
        )
        session.commit()
        raise AuthorizationDeniedError("Active organization selection is required.")

    if principal.selected_organization_id != organization_id:
        SecurityAuditRepository.append_event(
            session,
            event_type="CROSS_TENANT_ACCESS_DENIED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code="organization_context_mismatch",
            payload_json={"required_permission": required_permission.value},
            user_id=principal.user_id,
            organization_id=principal.selected_organization_id,
            session_id=principal.session_id,
            correlation_id=correlation_id,
            created_at=now,
        )
        session.commit()
        raise AuthorizationDeniedError(
            "Requested organization does not match authenticated active organization."
        )

    found = IdentityAndSessionRepository.get_active_membership_for_org(
        session, user_id=principal.user_id, organization_id=organization_id
    )
    if found is None:
        SecurityAuditRepository.append_event(
            session,
            event_type="TENANT_MEMBERSHIP_DENIED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code="membership_inactive_or_missing",
            payload_json={"required_permission": required_permission.value},
            user_id=principal.user_id,
            organization_id=None,
            session_id=principal.session_id,
            correlation_id=correlation_id,
            created_at=now,
        )
        session.commit()
        raise AuthorizationDeniedError("Active membership required in target organization.")

    membership, org = found
    role = OrganizationRole(membership.role)
    authorized = AuthorizedTenantPrincipal(
        session=principal,
        organization_id=org.id,
        membership_id=membership.id,
        role=role,
        permissions=permissions_for_role(role),
    )
    try:
        require_tenant_permission(
            authorized,
            required_permission,
            target_organization_id=org.id,
        )
    except AuthorizationDeniedError:
        SecurityAuditRepository.append_event(
            session,
            event_type="RBAC_PERMISSION_DENIED",
            outcome=SecurityAuditOutcome.DENIED,
            reason_code=f"missing_{required_permission.value}",
            payload_json={"role": membership.role, "permission": required_permission.value},
            user_id=principal.user_id,
            organization_id=org.id,
            session_id=principal.session_id,
            correlation_id=correlation_id,
            created_at=now,
        )
        AuditEventRepository.append_event(
            session,
            TenantContext(
                organization_id=org.id,
                actor_user_id=principal.user_id,
                source="authenticated_request",
            ),
            event_type="RBAC_PERMISSION_DENIED",
            target_entity_type="organization",
            target_entity_id=org.id,
            payload_json={"role": membership.role, "permission": required_permission.value},
            created_at=now,
        )
        session.commit()
        raise

    apply_pg_rls_context(session, organization_id=org.id, user_id=principal.user_id)
    return AuthorizedMembershipContext(principal=authorized, organization=org)


def logout_session(
    session: Session,
    *,
    principal: AuthenticatedSessionPrincipal,
    oidc_adapter: OidcProviderAdapter,
    correlation_id: str | None = None,
) -> str | None:
    """Revoke server-side session and emit optional RP-initiated logout redirect URL."""
    now = utc_now().astimezone(timezone.utc)
    IdentityAndSessionRepository.revoke_session(
        session, session_id=principal.session_id, now=now, reason="explicit_logout"
    )
    SecurityAuditRepository.append_event(
        session,
        event_type="AUTH_LOGOUT_SUCCEEDED",
        outcome=SecurityAuditOutcome.SUCCESS,
        reason_code="explicit_logout",
        payload_json={"revoked": True},
        user_id=principal.user_id,
        organization_id=principal.selected_organization_id,
        session_id=principal.session_id,
        correlation_id=correlation_id,
        created_at=now,
    )
    session.commit()
    return oidc_adapter.build_logout_url()
