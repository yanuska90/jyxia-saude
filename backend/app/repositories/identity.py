"""Repositories for federated OIDC identity, sessions, and security audit logging."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select, text, update
from sqlalchemy.exc import IntegrityError, OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.core.constants import (
    ExternalIdentityStatus,
    MembershipStatus,
    OrganizationStatus,
    SecurityAuditOutcome,
)
from app.db.base import new_uuid, utc_now
from app.db.session import apply_pg_identity_context, apply_pg_rls_context
from app.models.entities import (
    SECURITY_AUDIT_SCHEMA_VERSION,
    AuthSession,
    ExternalIdentity,
    OidcAuthState,
    Organization,
    OrganizationMembership,
    SecurityAuditEvent,
    User,
)
from app.repositories.institutional import (
    GENESIS_AUDIT_HASH,
    _sqlite_lock_for,
    assert_safe_audit_payload,
    normalize_audit_timestamp,
)
from app.schemas.tenant import TenantContext

_SECURITY_AUDIT_LOCK_KEY = "__global_security_audit__"


@dataclass(frozen=True, slots=True)
class SecurityAuditVerificationResult:
    valid: bool
    event_count: int
    failure_reason: str | None = None
    broken_sequence: int | None = None


def hash_external_subject(issuer: str, subject: str) -> str:
    """Hash external (issuer, subject) deterministically without storing clear external IDs in audit."""
    return hashlib.sha256(f"{issuer}\x00{subject}".encode("utf-8")).hexdigest()


def compute_security_event_hash(
    *,
    schema_version: str = SECURITY_AUDIT_SCHEMA_VERSION,
    sequence_number: int,
    event_type: str,
    outcome: str,
    user_id: str | None,
    organization_id: str | None,
    issuer: str | None,
    subject_hash: str | None,
    session_id: str | None,
    correlation_id: str | None,
    reason_code: str,
    created_at: datetime,
    payload_json: dict[str, Any],
    prev_event_hash: str,
) -> str:
    """Compute canonical SHA-256 hash linking every security audit event in sequence."""
    canonical = json.dumps(
        {
            "schema_version": schema_version,
            "sequence_number": sequence_number,
            "event_type": event_type,
            "outcome": outcome,
            "user_id": user_id,
            "organization_id": organization_id,
            "issuer": issuer,
            "subject_hash": subject_hash,
            "session_id": session_id,
            "correlation_id": correlation_id,
            "reason_code": reason_code,
            "created_at": normalize_audit_timestamp(created_at),
            "payload_json": payload_json,
            "prev_event_hash": prev_event_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class IdentityAndSessionRepository:
    """Persistence operations for external OIDC identities, auth states, and sessions."""

    @staticmethod
    def bind_external_identity(
        session: Session,
        *,
        user_id: str,
        issuer: str,
        subject: str,
        email_at_binding: str | None = None,
        status: str = ExternalIdentityStatus.ACTIVE.value,
    ) -> ExternalIdentity:
        cleaned_issuer = issuer.strip()
        cleaned_subject = subject.strip()
        apply_pg_rls_context(session, organization_id=None, user_id=user_id)
        apply_pg_identity_context(
            session,
            oidc_issuer=cleaned_issuer,
            oidc_subject=cleaned_subject,
        )
        identity = ExternalIdentity(
            user_id=user_id,
            issuer=cleaned_issuer,
            subject=cleaned_subject,
            email_at_binding=email_at_binding.strip().lower() if email_at_binding else None,
            status=status,
        )
        session.add(identity)
        session.flush()
        return identity

    @staticmethod
    def get_external_identity_by_issuer_subject(
        session: Session,
        *,
        issuer: str,
        subject: str,
        oidc_state_hash: str | None = None,
    ) -> tuple[ExternalIdentity, User] | None:
        """Resolve institutional user STRICTLY by (issuer, subject), never by email."""
        apply_pg_identity_context(
            session,
            oidc_state_hash=oidc_state_hash,
            oidc_issuer=issuer,
            oidc_subject=subject,
        )
        row = session.execute(
            select(ExternalIdentity, User)
            .join(User, User.id == ExternalIdentity.user_id)
            .where(
                ExternalIdentity.issuer == issuer,
                ExternalIdentity.subject == subject,
            )
        ).first()
        if row is None:
            return None
        apply_pg_rls_context(session, organization_id=None, user_id=row[1].id)
        return row[0], row[1]

    @staticmethod
    def touch_external_identity_login(
        session: Session, identity_id: str, *, authenticated_at: datetime
    ) -> None:
        session.execute(
            update(ExternalIdentity)
            .where(ExternalIdentity.id == identity_id)
            .values(last_authenticated_at=authenticated_at, updated_at=authenticated_at)
        )

    @staticmethod
    def create_oidc_auth_state(
        session: Session,
        *,
        state_hash: str,
        nonce_hash: str,
        code_verifier_ciphertext: str,
        issuer: str,
        redirect_uri: str,
        next_path: str | None,
        expires_at: datetime,
    ) -> OidcAuthState:
        apply_pg_identity_context(session, oidc_state_hash=state_hash)
        row = OidcAuthState(
            state_hash=state_hash,
            nonce_hash=nonce_hash,
            code_verifier_ciphertext=code_verifier_ciphertext,
            issuer=issuer,
            redirect_uri=redirect_uri,
            next_path=next_path,
            expires_at=expires_at,
        )
        session.add(row)
        session.flush()
        return row

    @staticmethod
    def consume_oidc_auth_state_atomic(
        session: Session, *, state_hash: str, now: datetime
    ) -> OidcAuthState | None:
        """Atomically consume a non-expired, unconsumed OIDC state entry once."""
        apply_pg_identity_context(session, oidc_state_hash=state_hash)
        row = session.scalar(
            select(OidcAuthState).where(
                OidcAuthState.state_hash == state_hash,
                OidcAuthState.consumed_at.is_(None),
                OidcAuthState.expires_at > now,
            )
        )
        if row is None:
            return None
        bind = session.get_bind()
        if bind is not None and bind.dialect.name == "postgresql":
            consumed_id = session.execute(
                text("SELECT public.jyxia_consume_oidc_auth_state(:p_state_hash, :p_now)"),
                {"p_state_hash": state_hash, "p_now": now},
            ).scalar()
            if consumed_id != row.id:
                return None
        else:
            result = session.execute(
                update(OidcAuthState)
                .where(
                    OidcAuthState.id == row.id,
                    OidcAuthState.state_hash == state_hash,
                    OidcAuthState.consumed_at.is_(None),
                    OidcAuthState.expires_at > now,
                )
                .values(consumed_at=now)
                .execution_options(synchronize_session=False)
            )
            if result.rowcount != 1:  # type: ignore[attr-defined]
                return None
        row.consumed_at = now
        return row

    @staticmethod
    def finalize_oidc_auth_state(
        session: Session, *, state_hash: str, now: datetime
    ) -> None:
        """Close a consumed OIDC state after callback finishes so it cannot be reused."""
        apply_pg_identity_context(session, oidc_state_hash=state_hash)
        bind = session.get_bind()
        if bind is not None and bind.dialect.name == "postgresql":
            session.execute(
                text("SELECT public.jyxia_finalize_oidc_auth_state(:p_state_hash)"),
                {"p_state_hash": state_hash},
            )
        else:
            session.execute(
                update(OidcAuthState)
                .where(OidcAuthState.state_hash == state_hash)
                .values(expires_at=now)
                .execution_options(synchronize_session=False)
            )

    @staticmethod
    def create_auth_session(
        session: Session,
        *,
        user_id: str,
        external_identity_id: str,
        active_organization_id: str | None,
        session_token_hash: str,
        csrf_token_hash: str,
        auth_method: str,
        acr: str,
        amr_json: list[str],
        mfa_verified_at: datetime,
        oidc_auth_time: datetime,
        idle_expires_at: datetime,
        absolute_expires_at: datetime,
        now: datetime,
        prev_session_token_hash: str | None = None,
        oidc_state_hash: str | None = None,
    ) -> AuthSession:
        apply_pg_rls_context(session, organization_id=active_organization_id, user_id=user_id)
        apply_pg_identity_context(
            session,
            session_token_hash=session_token_hash,
            prev_session_token_hash=prev_session_token_hash,
            oidc_state_hash=oidc_state_hash,
        )
        row = AuthSession(
            user_id=user_id,
            external_identity_id=external_identity_id,
            active_organization_id=active_organization_id,
            session_token_hash=session_token_hash,
            csrf_token_hash=csrf_token_hash,
            auth_method=auth_method,
            acr=acr,
            amr_json=amr_json,
            mfa_verified_at=mfa_verified_at,
            oidc_auth_time=oidc_auth_time,
            idle_expires_at=idle_expires_at,
            absolute_expires_at=absolute_expires_at,
            last_seen_at=now,
            created_at=now,
        )
        session.add(row)
        session.flush()
        return row

    @staticmethod
    def get_session_with_identity(
        session: Session, *, session_token_hash: str
    ) -> tuple[AuthSession, User, ExternalIdentity] | None:
        apply_pg_identity_context(session, session_token_hash=session_token_hash)
        row = session.execute(
            select(AuthSession, User, ExternalIdentity)
            .join(User, User.id == AuthSession.user_id)
            .join(ExternalIdentity, ExternalIdentity.id == AuthSession.external_identity_id)
            .where(AuthSession.session_token_hash == session_token_hash)
        ).first()
        if row is None:
            return None
        apply_pg_rls_context(
            session,
            organization_id=row[0].active_organization_id,
            user_id=row[1].id,
        )
        return row[0], row[1], row[2]

    @staticmethod
    def touch_auth_session(
        session: Session, *, session_id: str, now: datetime, new_idle_expires_at: datetime
    ) -> None:
        session.execute(
            update(AuthSession)
            .where(AuthSession.id == session_id)
            .values(last_seen_at=now, idle_expires_at=new_idle_expires_at)
        )

    @staticmethod
    def set_session_active_organization(
        session: Session, *, session_id: str, organization_id: str | None
    ) -> None:
        session.execute(
            update(AuthSession)
            .where(AuthSession.id == session_id)
            .values(active_organization_id=organization_id)
        )

    @staticmethod
    def revoke_session(
        session: Session,
        *,
        session_id: str,
        now: datetime,
        reason: str,
        session_token_hash: str | None = None,
    ) -> None:
        if session_token_hash is not None:
            apply_pg_identity_context(session, session_token_hash=session_token_hash)
        bind = session.get_bind()
        if bind is not None and bind.dialect.name == "postgresql":
            session.execute(
                text(
                    "SELECT public.jyxia_revoke_auth_session(:p_session_id, :p_reason, :p_now)"
                ),
                {
                    "p_session_id": session_id,
                    "p_reason": reason[:120],
                    "p_now": now,
                },
            )
        else:
            session.execute(
                update(AuthSession)
                .where(AuthSession.id == session_id, AuthSession.revoked_at.is_(None))
                .values(revoked_at=now, revocation_reason=reason[:120])
                .execution_options(synchronize_session=False)
            )

    @staticmethod
    def revoke_all_user_sessions(
        session: Session, *, user_id: str, now: datetime, reason: str
    ) -> int:
        apply_pg_rls_context(session, organization_id=None, user_id=user_id)
        result = session.execute(
            update(AuthSession)
            .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
            .values(revoked_at=now, revocation_reason=reason[:120])
        )
        return int(result.rowcount or 0)  # type: ignore[attr-defined]

    @staticmethod
    def list_user_active_memberships(
        session: Session, *, user_id: str
    ) -> list[tuple[OrganizationMembership, Organization]]:
        """List caller's active memberships across active organizations under PostgreSQL RLS."""
        apply_pg_rls_context(session, organization_id=None, user_id=user_id)
        rows = session.execute(
            select(OrganizationMembership, Organization)
            .join(Organization, Organization.id == OrganizationMembership.organization_id)
            .where(
                OrganizationMembership.user_id == user_id,
                OrganizationMembership.status == MembershipStatus.ACTIVE.value,
                Organization.status == OrganizationStatus.ACTIVE.value,
            )
            .order_by(Organization.name.asc())
        ).all()
        return [(membership, org) for membership, org in rows]

    @staticmethod
    def get_active_membership_for_org(
        session: Session, *, user_id: str, organization_id: str
    ) -> tuple[OrganizationMembership, Organization] | None:
        """Resolve an active membership in an active organization under tenant RLS."""
        apply_pg_rls_context(session, organization_id=organization_id, user_id=user_id)
        row = session.execute(
            select(OrganizationMembership, Organization)
            .join(Organization, Organization.id == OrganizationMembership.organization_id)
            .where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == user_id,
                OrganizationMembership.status == MembershipStatus.ACTIVE.value,
                Organization.status == OrganizationStatus.ACTIVE.value,
            )
        ).first()
        if row is None:
            apply_pg_rls_context(session, organization_id=None, user_id=user_id)
            return None
        return row[0], row[1]


class SecurityAuditRepository:
    """Append-only global ledger for authentication, MFA, session, and RBAC refusal events."""

    @staticmethod
    def append_event(
        session: Session,
        *,
        event_type: str,
        outcome: SecurityAuditOutcome | str,
        reason_code: str,
        payload_json: dict[str, Any],
        user_id: str | None = None,
        organization_id: str | None = None,
        issuer: str | None = None,
        subject: str | None = None,
        session_id: str | None = None,
        session_token_hash: str | None = None,
        oidc_state_hash: str | None = None,
        correlation_id: str | None = None,
        created_at: datetime | None = None,
    ) -> SecurityAuditEvent:
        safe_payload = assert_safe_audit_payload(payload_json)
        outcome_val = outcome.value if isinstance(outcome, SecurityAuditOutcome) else str(outcome)
        subject_hash = (
            hash_external_subject(issuer, subject) if (issuer and subject) else None
        )
        timestamp = (created_at or utc_now()).astimezone(timezone.utc)

        bind = session.get_bind()
        is_pg = bind is not None and bind.dialect.name == "postgresql"

        if is_pg:
            apply_pg_rls_context(
                session,
                organization_id=organization_id,
                user_id=user_id,
            )
            apply_pg_identity_context(
                session,
                session_token_hash=session_token_hash,
                oidc_state_hash=oidc_state_hash,
                oidc_issuer=issuer,
                oidc_subject=subject,
            )
            session.execute(text("SELECT pg_advisory_xact_lock(9021042)"))
            head_row = session.execute(
                text("SELECT last_sequence, last_event_hash FROM public.jyxia_get_security_audit_head()")
            ).first()
            last_seq = int(head_row[0]) if head_row is not None else 0
            prev_hash = str(head_row[1]) if head_row is not None else GENESIS_AUDIT_HASH
            next_seq = last_seq + 1
            event_hash = compute_security_event_hash(
                schema_version=SECURITY_AUDIT_SCHEMA_VERSION,
                sequence_number=next_seq,
                event_type=event_type,
                outcome=outcome_val,
                user_id=user_id,
                organization_id=organization_id,
                issuer=issuer,
                subject_hash=subject_hash,
                session_id=session_id,
                correlation_id=correlation_id,
                reason_code=reason_code,
                created_at=timestamp,
                payload_json=safe_payload,
                prev_event_hash=prev_hash,
            )
            event_id = new_uuid()
            session.execute(
                text(
                    "SELECT public.jyxia_append_security_event("
                    ":p_id, :p_schema_version, :p_sequence_number, :p_event_type, :p_outcome, "
                    ":p_user_id, :p_organization_id, :p_issuer, :p_subject_hash, :p_session_id, "
                    ":p_correlation_id, :p_reason_code, :p_payload_json, :p_prev_event_hash, "
                    ":p_event_hash, :p_created_at)"
                ),
                {
                    "p_id": event_id,
                    "p_schema_version": SECURITY_AUDIT_SCHEMA_VERSION,
                    "p_sequence_number": next_seq,
                    "p_event_type": event_type,
                    "p_outcome": outcome_val,
                    "p_user_id": user_id,
                    "p_organization_id": organization_id,
                    "p_issuer": issuer,
                    "p_subject_hash": subject_hash,
                    "p_session_id": session_id,
                    "p_correlation_id": correlation_id,
                    "p_reason_code": reason_code,
                    "p_payload_json": json.dumps(safe_payload, ensure_ascii=True),
                    "p_prev_event_hash": prev_hash,
                    "p_event_hash": event_hash,
                    "p_created_at": timestamp,
                },
            )
            return SecurityAuditEvent(
                id=event_id,
                schema_version=SECURITY_AUDIT_SCHEMA_VERSION,
                sequence_number=next_seq,
                event_type=event_type,
                outcome=outcome_val,
                user_id=user_id,
                organization_id=organization_id,
                issuer=issuer,
                subject_hash=subject_hash,
                session_id=session_id,
                correlation_id=correlation_id,
                reason_code=reason_code,
                payload_json=safe_payload,
                prev_event_hash=prev_hash,
                event_hash=event_hash,
                created_at=timestamp,
            )

        latest = session.scalar(
            select(SecurityAuditEvent).order_by(SecurityAuditEvent.sequence_number.desc()).limit(1)
        )
        next_seq = 1 if latest is None else latest.sequence_number + 1
        prev_hash = GENESIS_AUDIT_HASH if latest is None else latest.event_hash
        event_hash = compute_security_event_hash(
            schema_version=SECURITY_AUDIT_SCHEMA_VERSION,
            sequence_number=next_seq,
            event_type=event_type,
            outcome=outcome_val,
            user_id=user_id,
            organization_id=organization_id,
            issuer=issuer,
            subject_hash=subject_hash,
            session_id=session_id,
            correlation_id=correlation_id,
            reason_code=reason_code,
            created_at=timestamp,
            payload_json=safe_payload,
            prev_event_hash=prev_hash,
        )
        row = SecurityAuditEvent(
            schema_version=SECURITY_AUDIT_SCHEMA_VERSION,
            sequence_number=next_seq,
            event_type=event_type,
            outcome=outcome_val,
            user_id=user_id,
            organization_id=organization_id,
            issuer=issuer,
            subject_hash=subject_hash,
            session_id=session_id,
            correlation_id=correlation_id,
            reason_code=reason_code,
            payload_json=safe_payload,
            prev_event_hash=prev_hash,
            event_hash=event_hash,
            created_at=timestamp,
        )
        session.add(row)
        session.flush()
        return row

    @staticmethod
    def append_event_atomic(
        session_factory: sessionmaker[Session] | Callable[[], Session],
        *,
        event_type: str,
        outcome: SecurityAuditOutcome | str,
        reason_code: str,
        payload_json: dict[str, Any],
        user_id: str | None = None,
        organization_id: str | None = None,
        issuer: str | None = None,
        subject: str | None = None,
        session_id: str | None = None,
        session_token_hash: str | None = None,
        oidc_state_hash: str | None = None,
        correlation_id: str | None = None,
        max_attempts: int = 8,
    ) -> SecurityAuditEvent:
        """Append and commit a security audit event in an isolated transaction."""
        last_error: Exception | None = None
        for attempt in range(1, max_attempts + 1):
            session = session_factory()
            bind = session.get_bind()
            is_sqlite = bind is not None and bind.dialect.name == "sqlite"
            lock_cm = _sqlite_lock_for(_SECURITY_AUDIT_LOCK_KEY) if is_sqlite else None
            try:
                if lock_cm is not None:
                    lock_cm.acquire()
                row = SecurityAuditRepository.append_event(
                    session,
                    event_type=event_type,
                    outcome=outcome,
                    reason_code=reason_code,
                    payload_json=payload_json,
                    user_id=user_id,
                    organization_id=organization_id,
                    issuer=issuer,
                    subject=subject,
                    session_id=session_id,
                    session_token_hash=session_token_hash,
                    oidc_state_hash=oidc_state_hash,
                    correlation_id=correlation_id,
                )
                session.commit()
                return row
            except (IntegrityError, OperationalError) as exc:
                session.rollback()
                last_error = exc
                if attempt < max_attempts:
                    time.sleep(0.01 * attempt)
            finally:
                if lock_cm is not None:
                    lock_cm.release()
                session.close()
        assert last_error is not None
        raise last_error

    @staticmethod
    def list_org_events(session: Session, ctx: TenantContext) -> list[SecurityAuditEvent]:
        apply_pg_rls_context(
            session, organization_id=ctx.organization_id, user_id=ctx.actor_user_id
        )
        return list(
            session.scalars(
                select(SecurityAuditEvent)
                .where(SecurityAuditEvent.organization_id == ctx.organization_id)
                .order_by(SecurityAuditEvent.sequence_number.asc())
            )
        )

    @staticmethod
    def verify_chain_detailed(session: Session) -> SecurityAuditVerificationResult:
        """Verify continuity of the global security_auth_events ledger (privileged/SQLite reads)."""
        events = list(
            session.scalars(
                select(SecurityAuditEvent).order_by(SecurityAuditEvent.sequence_number.asc())
            )
        )
        expected_prev = GENESIS_AUDIT_HASH
        for expected_seq, ev in enumerate(events, start=1):
            if ev.schema_version != SECURITY_AUDIT_SCHEMA_VERSION:
                return SecurityAuditVerificationResult(
                    valid=False,
                    event_count=len(events),
                    failure_reason="unsupported_schema_version",
                    broken_sequence=ev.sequence_number,
                )
            if ev.sequence_number != expected_seq:
                return SecurityAuditVerificationResult(
                    valid=False,
                    event_count=len(events),
                    failure_reason="sequence_gap_or_reorder",
                    broken_sequence=expected_seq,
                )
            if ev.prev_event_hash != expected_prev:
                return SecurityAuditVerificationResult(
                    valid=False,
                    event_count=len(events),
                    failure_reason="prev_event_hash_mismatch",
                    broken_sequence=expected_seq,
                )
            recomputed = compute_security_event_hash(
                schema_version=ev.schema_version,
                sequence_number=ev.sequence_number,
                event_type=ev.event_type,
                outcome=ev.outcome,
                user_id=ev.user_id,
                organization_id=ev.organization_id,
                issuer=ev.issuer,
                subject_hash=ev.subject_hash,
                session_id=ev.session_id,
                correlation_id=ev.correlation_id,
                reason_code=ev.reason_code,
                created_at=ev.created_at,
                payload_json=ev.payload_json,
                prev_event_hash=ev.prev_event_hash,
            )
            if ev.event_hash != recomputed:
                return SecurityAuditVerificationResult(
                    valid=False,
                    event_count=len(events),
                    failure_reason="event_hash_mismatch",
                    broken_sequence=expected_seq,
                )
            expected_prev = ev.event_hash
        return SecurityAuditVerificationResult(valid=True, event_count=len(events))

    @staticmethod
    def verify_chain(session: Session) -> bool:
        return SecurityAuditRepository.verify_chain_detailed(session).valid

    @staticmethod
    def count_all_events(session: Session) -> int:
        return int(session.scalar(select(func.count(SecurityAuditEvent.id))) or 0)
