"""End-to-end tests for (issuer, subject) binding, cookie sessions, CSRF, multi-tenancy & 5-role RBAC."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs, urlparse

from fastapi.testclient import TestClient
from sqlalchemy import select, update

from app.core.constants import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    SESSION_COOKIE_NAME,
    CaseReadinessState,
    ExternalIdentityStatus,
    MembershipStatus,
    OrganizationRole,
)
from app.core.oidc import StandardOidcProviderAdapter
from app.db.session import create_session_factory
from app.main import create_app
from app.models.entities import AuthSession, ExternalIdentity, SecurityAuditEvent, User
from app.repositories.identity import IdentityAndSessionRepository, SecurityAuditRepository
from app.repositories.institutional import (
    AuditEventRepository,
    CaseAndDocumentRepository,
    OrganizationRepository,
)
from app.schemas.tenant import TenantContext
from tests.backend.oidc_test_support import (
    MockOidcProviderState,
    _base_claims,
    _oidc_settings,
    _sign_id_token,
)


def _login_user_via_bff(
    client: TestClient,
    idp: MockOidcProviderState,
    *,
    sub: str,
    email: str,
    code: str,
) -> tuple[str, str]:
    login_resp = client.get("/api/v1/auth/login?next=/cases", follow_redirects=False)
    assert login_resp.status_code == 302
    params = parse_qs(urlparse(login_resp.headers["location"]).query)
    state = params["state"][0]
    nonce = params["nonce"][0]
    challenge = params["code_challenge"][0]

    claims = _base_claims(issuer=idp.issuer, sub=sub, nonce=nonce)
    claims["email"] = email
    idp.issued_codes[code] = {
        "code_challenge": challenge,
        "id_token": _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=claims),
    }

    cb = client.get(f"/api/v1/auth/callback?code={code}&state={state}", follow_redirects=False)
    assert cb.status_code == 302
    sess_cookie = cb.cookies.get(SESSION_COOKIE_NAME)
    csrf_cookie = cb.cookies.get(CSRF_COOKIE_NAME)
    assert sess_cookie and csrf_cookie
    return sess_cookie, csrf_cookie


def test_identity_issuer_subject_binding_blocks_unprovisioned_and_email_spoof(
    migrated_engine,
) -> None:
    idp = MockOidcProviderState()
    settings = _oidc_settings()
    adapter = StandardOidcProviderAdapter(settings, transport=idp.transport())
    factory = create_session_factory(migrated_engine)

    db = factory()
    try:
        org = OrganizationRepository.create_organization(session=db, slug="hosp-a", name="Hospital Alpha")
        user_bound = OrganizationRepository.create_user(
            db, email="original@jyxia.local", display_name="Bound User", mfa_enrolled=True
        )
        OrganizationRepository.assign_membership(
            db, TenantContext(organization_id=org.id), user_id=user_bound.id, role=OrganizationRole.ORG_ADMIN.value
        )
        IdentityAndSessionRepository.bind_external_identity(
            db, user_id=user_bound.id, issuer=idp.issuer, subject="sub-bound-1", email_at_binding="original@jyxia.local"
        )
        # Same email exists on another user WITHOUT external_identity binding -> MUST NEVER match by email!
        OrganizationRepository.create_user(
            db, email="unlinked@jyxia.local", display_name="Unlinked Email User", mfa_enrolled=True
        )
        # User with active external_identity on DIFFERENT issuer with colliding sub="sub-bound-1" cannot leak
        other_user = OrganizationRepository.create_user(
            db, email="other-idp@jyxia.local", display_name="Other IdP User", mfa_enrolled=True
        )
        IdentityAndSessionRepository.bind_external_identity(
            db,
            user_id=other_user.id,
            issuer="https://other-idp.example",
            subject="sub-colliding",
        )
        db.commit()
    finally:
        db.close()

    app = create_app(settings, engine=migrated_engine, oidc_adapter=adapter)
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        # 1. Bound user changes email at IdP -> still resolves cleanly via (issuer, subject)!
        s1, _csrf1 = _login_user_via_bff(
            client, idp, sub="sub-bound-1", email="renamed.at.idp@jyxia.local", code="c-bound"
        )
        me = client.get("/api/v1/me")
        assert me.status_code == 200
        assert me.json()["user_id"] == user_bound.id
        assert "no-store" in me.headers.get("cache-control", "")

        # DB session table MUST NOT contain raw cookie token or plaintext CSRF token
        check_db = factory()
        try:
            sess_row = check_db.scalar(select(AuthSession))
            assert sess_row is not None
            assert sess_row.session_token_hash != s1
            assert len(sess_row.session_token_hash) == 64
        finally:
            check_db.close()

        # 2. Pre-existing cookie BEFORE new login gets cleanly replaced (Session Fixation prevention!)
        client2 = TestClient(app, base_url="http://127.0.0.1:8000")
        client2.cookies.set(
            SESSION_COOKIE_NAME,
            "stale_attacker_fixated_session_value_0000",
            domain="127.0.0.1",
            path="/",
        )
        s2, _ = _login_user_via_bff(
            client2, idp, sub="sub-bound-1", email="renamed.at.idp@jyxia.local", code="c-fixation"
        )
        assert s2 != "stale_attacker_fixated_session_value_0000"
        assert s2 != s1

    # 3. Unknown subject matching existing email (`unlinked@jyxia.local`) DENIED 403 & no auto-provisioning
    with TestClient(app, base_url="http://127.0.0.1:8000") as unbound_client:
        login = unbound_client.get("/api/v1/auth/login", follow_redirects=False)
        params = parse_qs(urlparse(login.headers["location"]).query)
        claims = _base_claims(issuer=idp.issuer, sub="sub-not-bound", nonce=params["nonce"][0])
        claims["email"] = "unlinked@jyxia.local"
        idp.issued_codes["c-unbound"] = {
            "code_challenge": params["code_challenge"][0],
            "id_token": _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=claims),
        }
        cb = unbound_client.get(
            f"/api/v1/auth/callback?code=c-unbound&state={params['state'][0]}",
            follow_redirects=False,
        )
        assert cb.status_code == 403

    # 4. Different issuer colliding subject (`sub-colliding`) on OUR issuer fails 403!
    with TestClient(app, base_url="http://127.0.0.1:8000") as collider_client:
        login = collider_client.get("/api/v1/auth/login", follow_redirects=False)
        params = parse_qs(urlparse(login.headers["location"]).query)
        claims = _base_claims(issuer=idp.issuer, sub="sub-colliding", nonce=params["nonce"][0])
        idp.issued_codes["c-collide"] = {
            "code_challenge": params["code_challenge"][0],
            "id_token": _sign_id_token(idp.rsa_priv, alg="RS256", kid=idp.rsa_jwk["kid"], claims=claims),
        }
        cb = collider_client.get(
            f"/api/v1/auth/callback?code=c-collide&state={params['state'][0]}",
            follow_redirects=False,
        )
        assert cb.status_code == 403

    with factory() as verify_session:
        assert SecurityAuditRepository.verify_chain(verify_session)


def test_session_timeouts_csrf_origin_logout_and_user_suspension(migrated_engine) -> None:
    idp = MockOidcProviderState()
    settings = _oidc_settings(session_idle_timeout_seconds=120, session_absolute_timeout_seconds=600)
    adapter = StandardOidcProviderAdapter(settings, transport=idp.transport())
    factory = create_session_factory(migrated_engine)

    db = factory()
    try:
        org = OrganizationRepository.create_organization(db, slug="sess-org", name="Session Org")
        user = OrganizationRepository.create_user(
            db, email="sess@jyxia.local", display_name="Session User", mfa_enrolled=True
        )
        OrganizationRepository.assign_membership(
            db, TenantContext(organization_id=org.id), user_id=user.id, role=OrganizationRole.ORG_ADMIN.value
        )
        IdentityAndSessionRepository.bind_external_identity(
            db, user_id=user.id, issuer=idp.issuer, subject="sub-sess"
        )
        db.commit()
    finally:
        db.close()

    app = create_app(settings, engine=migrated_engine, oidc_adapter=adapter)
    with TestClient(app, base_url="http://127.0.0.1:8000") as client:
        _, csrf_tok = _login_user_via_bff(
            client, idp, sub="sub-sess", email="sess@jyxia.local", code="c-s1"
        )
        sess_info = client.get("/api/v1/auth/session")
        assert sess_info.status_code == 200
        assert sess_info.json()["authenticated"] is True
        sess_id = sess_info.json()["session_id"]

        #CSRF & Origin defense matrix on POST /auth/logout and /auth/select-organization
        assert client.post("/api/v1/auth/logout").status_code == 403  # no Origin / no CSRF
        assert (
            client.post(
                "/api/v1/auth/logout",
                headers={"Origin": "https://evil.invalid", CSRF_HEADER_NAME: csrf_tok},
            ).status_code
            == 403
        )
        # Present-but-invalid Origin ('null', malformed, wrong scheme, port, subdomain, userinfo)
        # MUST ALWAYS fail 403 even when accompanied by a valid trusted Referer!
        for rejected_origin in (
            "null",
            "NULL",
            "invalid-origin-value",
            "https://evil.invalid",
            "http://sub.127.0.0.1:8000",
            "http://127.0.0.1.evil.invalid:8000",
            "http://127.0.0.1:8001",
            "http://127.0.0.1:9999",
            "https://127.0.0.1:8000",
            "http://user:pass@127.0.0.1:8000",
            "http://127.0.0.1:8000/extra-path",
            "http://127.0.0.1:8000?query=1",
        ):
            assert (
                client.post(
                    "/api/v1/auth/logout",
                    headers={
                        "Origin": rejected_origin,
                        "Referer": "http://127.0.0.1:8000/workspace",
                        CSRF_HEADER_NAME: csrf_tok,
                    },
                ).status_code
                == 403
            ), f"Origin={rejected_origin!r} must be rejected without Referer fallback"
            assert (
                client.post(
                    "/api/v1/auth/select-organization",
                    json={"organization_id": org.id},
                    headers={
                        "Origin": rejected_origin,
                        "Referer": "http://127.0.0.1:8000/workspace",
                        CSRF_HEADER_NAME: csrf_tok,
                    },
                ).status_code
                == 403
            )

        # Absent Origin with invalid Referer MUST fail 403
        for bad_referer in (
            "https://evil.invalid/workspace",
            "http://127.0.0.1:8001/workspace",
            "http://sub.127.0.0.1:8000/workspace",
            "http://user@127.0.0.1:8000/workspace",
            "null",
        ):
            assert (
                client.post(
                    "/api/v1/auth/logout",
                    headers={"Referer": bad_referer, CSRF_HEADER_NAME: csrf_tok},
                ).status_code
                == 403
            )

        # Absent Origin with valid Referer is accepted when CSRF token is valid
        ref_select = client.post(
            "/api/v1/auth/select-organization",
            json={"organization_id": org.id},
            headers={"Referer": "http://127.0.0.1:8000/workspace?view=cases", CSRF_HEADER_NAME: csrf_tok},
        )
        assert ref_select.status_code == 200
        csrf_tok = ref_select.cookies.get(CSRF_COOKIE_NAME) or csrf_tok

        # Missing CSRF header or mismatched CSRF header MUST fail 403
        assert (
            client.post(
                "/api/v1/auth/logout",
                headers={"Origin": "http://127.0.0.1:8000"},
            ).status_code
            == 403
        )
        assert (
            client.post(
                "/api/v1/auth/logout",
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: "wrong-csrf-tok"},
            ).status_code
            == 403
        )
        # Attacker attempts matching cookie+header double-submit forgery that doesn't match DB digest!
        client.cookies.set(
            CSRF_COOKIE_NAME,
            "forged-value-both-places-0000",
            domain="127.0.0.1",
            path="/",
        )
        assert (
            client.post(
                "/api/v1/auth/logout",
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: "forged-value-both-places-0000"},
            ).status_code
            == 403
        )

        # Restore genuine CSRF token -> valid logout succeeds cleanly
        client.cookies.set(CSRF_COOKIE_NAME, csrf_tok, domain="127.0.0.1", path="/")
        out = client.post(
            "/api/v1/auth/logout",
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_tok},
        )
        assert out.status_code == 200
        assert out.json()["logged_out"] is True
        assert "/protocol/openid-connect/logout" in (out.json()["end_session_url"] or "")
        assert client.get("/api/v1/me").status_code == 401

        # Second login -> simulate idle timeout expiry -> 401!
        _login_user_via_bff(client, idp, sub="sub-sess", email="sess@jyxia.local", code="c-s2")
        sess_id_2 = client.get("/api/v1/auth/session").json()["session_id"]
        assert sess_id_2 != sess_id
        db_exp = factory()
        try:
            now_utc = datetime.now(timezone.utc)
            db_exp.execute(
                update(AuthSession)
                .where(AuthSession.id == sess_id_2)
                .values(
                    created_at=now_utc - timedelta(minutes=10),
                    idle_expires_at=now_utc - timedelta(seconds=5),
                )
            )
            db_exp.commit()
        finally:
            db_exp.close()
        assert client.get("/api/v1/me").status_code == 401

        # Simulate absolute timeout expiry + bulk revocation cleanly as well
        _login_user_via_bff(client, idp, sub="sub-sess", email="sess@jyxia.local", code="c-s2-abs")
        sess_id_abs = client.get("/api/v1/auth/session").json()["session_id"]
        db_abs = factory()
        try:
            now_utc = datetime.now(timezone.utc)
            db_abs.execute(
                update(AuthSession)
                .where(AuthSession.id == sess_id_abs)
                .values(
                    created_at=now_utc - timedelta(hours=10),
                    idle_expires_at=now_utc + timedelta(minutes=5),
                    absolute_expires_at=now_utc - timedelta(seconds=10),
                )
            )
            db_abs.commit()
        finally:
            db_abs.close()
        assert client.get("/api/v1/me").status_code == 401

        # Third login -> simulate ExternalIdentity SUSPENDED status mid-session -> immediately rejected 401!
        _login_user_via_bff(client, idp, sub="sub-sess", email="sess@jyxia.local", code="c-s3-id-susp")
        db_id_susp = factory()
        try:
            db_id_susp.execute(
                update(ExternalIdentity)
                .where(ExternalIdentity.user_id == user.id)
                .values(status=ExternalIdentityStatus.SUSPENDED.value)
            )
            db_id_susp.commit()
        finally:
            db_id_susp.close()
        assert client.get("/api/v1/me").status_code == 401

        # Re-activate ExternalIdentity, then simulate user deactivation mid-session -> immediately rejected 401!
        db_id_react = factory()
        try:
            db_id_react.execute(
                update(ExternalIdentity)
                .where(ExternalIdentity.user_id == user.id)
                .values(status=ExternalIdentityStatus.ACTIVE.value)
            )
            db_id_react.commit()
        finally:
            db_id_react.close()

        _login_user_via_bff(client, idp, sub="sub-sess", email="sess@jyxia.local", code="c-s3")
        db_suspend = factory()
        try:
            db_suspend.execute(update(User).where(User.id == user.id).values(is_active=False))
            db_suspend.commit()
        finally:
            db_suspend.close()
        assert client.get("/api/v1/me").status_code == 401

    with factory() as verify_session:
        assert SecurityAuditRepository.verify_chain(verify_session)


def test_complete_five_role_rbac_matrix_and_multi_tenant_isolation(migrated_engine) -> None:
    idp = MockOidcProviderState()
    settings = _oidc_settings()
    adapter = StandardOidcProviderAdapter(settings, transport=idp.transport())
    factory = create_session_factory(migrated_engine)

    role_expectations: dict[OrganizationRole, dict[str, int]] = {
        OrganizationRole.ORG_ADMIN: {"access-context": 200, "cases": 200, "members": 200, "audit-events": 200},
        OrganizationRole.ADMIN_OPERATOR: {"access-context": 200, "cases": 200, "members": 200, "audit-events": 403},
        OrganizationRole.CLINICAL_REVIEWER: {"access-context": 200, "cases": 200, "members": 403, "audit-events": 403},
        OrganizationRole.AUDITOR_READONLY: {"access-context": 200, "cases": 200, "members": 200, "audit-events": 200},
        OrganizationRole.READ_ONLY: {"access-context": 200, "cases": 200, "members": 403, "audit-events": 403},
    }

    db = factory()
    try:
        org_a = OrganizationRepository.create_organization(db, slug="hosp-a", name="Hospital A")
        org_b = OrganizationRepository.create_organization(db, slug="hosp-b", name="Hospital B")
        CaseAndDocumentRepository.create_case(
            db,
            TenantContext(organization_id=org_a.id),
            case_code="CASE-A-001",
            external_reference="EXT-A1",
            procedure_reference="PROC-1",
            declared_laterality="esquerda",
            readiness_state=CaseReadinessState.PENDENTE.value,
        )
        CaseAndDocumentRepository.create_case(
            db,
            TenantContext(organization_id=org_b.id),
            case_code="CASE-B-001",
            external_reference="EXT-B1",
            procedure_reference="PROC-2",
            declared_laterality="direita",
            readiness_state=CaseReadinessState.PENDENTE.value,
        )

        # Create one user per RBAC role in org_a + multi-org user + user with suspended membership
        role_users: dict[OrganizationRole, str] = {}
        for role in OrganizationRole:
            u = OrganizationRepository.create_user(
                db, email=f"{role.value}@jyxia.local", display_name=f"Role {role.value}", mfa_enrolled=True
            )
            OrganizationRepository.assign_membership(
                db, TenantContext(organization_id=org_a.id), user_id=u.id, role=role.value
            )
            IdentityAndSessionRepository.bind_external_identity(
                db, user_id=u.id, issuer=idp.issuer, subject=f"sub-{role.value}"
            )
            role_users[role] = u.id

        multi_user = OrganizationRepository.create_user(
            db, email="multi@jyxia.local", display_name="Multi Tenant", mfa_enrolled=True
        )
        m_a = OrganizationRepository.assign_membership(
            db, TenantContext(organization_id=org_a.id), user_id=multi_user.id, role=OrganizationRole.READ_ONLY.value
        )
        OrganizationRepository.assign_membership(
            db, TenantContext(organization_id=org_b.id), user_id=multi_user.id, role=OrganizationRole.ORG_ADMIN.value
        )
        IdentityAndSessionRepository.bind_external_identity(
            db, user_id=multi_user.id, issuer=idp.issuer, subject="sub-multi"
        )
        db.commit()
    finally:
        db.close()

    app = create_app(settings, engine=migrated_engine, oidc_adapter=adapter)

    # 1. Verify full 5-role RBAC permission matrix, zero cross-tenant access to org_b,
    #    and canonical external serialization of 'document_reviewer' in JSON and OpenAPI (ACH-10)
    openapi_doc = app.openapi()
    openapi_role_enum = (
        openapi_doc.get("components", {})
        .get("schemas", {})
        .get("OrganizationRole", {})
        .get("enum", [])
    )
    assert openapi_role_enum == [
        "org_admin",
        "document_reviewer",
        "admin_operator",
        "auditor_readonly",
        "read_only",
    ]
    assert "clinical_reviewer" not in openapi_role_enum

    for idx, role in enumerate(OrganizationRole):
        with TestClient(app, base_url="http://127.0.0.1:8000") as client:
            _login_user_via_bff(
                client, idp, sub=f"sub-{role.value}", email=f"{role.value}@jyxia.local", code=f"c-r-{idx}"
            )
            my_orgs = client.get("/api/v1/me/organizations")
            assert my_orgs.status_code == 200
            assert my_orgs.json()["organizations"][0]["role"] == role.value
            if role == OrganizationRole.DOCUMENT_REVIEWER:
                assert my_orgs.json()["organizations"][0]["role"] == "document_reviewer"

            for ep, expected_code in role_expectations[role].items():
                res = client.get(f"/api/v1/organizations/{org_a.id}/{ep}")
                assert res.status_code == expected_code, f"Role {role.value} endpoint {ep} expected {expected_code}, got {res.status_code}"
                if ep == "access-context" and res.status_code == 200:
                    assert res.json()["role"] == role.value
                    if role == OrganizationRole.DOCUMENT_REVIEWER:
                        assert res.json()["role"] == "document_reviewer"
                if ep == "cases" and res.status_code == 200:
                    assert res.json()["role"] == role.value
                    cases = res.json()["cases"]
                    assert len(cases) == 1
                    assert cases[0]["case_code"] == "CASE-A-001"
                    assert cases[0]["administrative_only"] is True
                    assert cases[0]["clinical_approval"] is False
                if ep == "members" and res.status_code == 200:
                    member_roles = {m["role"] for m in res.json()["members"]}
                    assert "document_reviewer" in member_roles
                    assert "clinical_reviewer" not in member_roles

            # Cross-tenant org_b MUST always return 403 + spoofed X-Organization-ID header MUST fail 403!
            assert client.get(f"/api/v1/organizations/{org_b.id}/cases").status_code == 403
            assert (
                client.get(
                    f"/api/v1/organizations/{org_a.id}/cases",
                    headers={"X-Organization-ID": org_b.id},
                ).status_code
                == 403
            )

    # 1b. Verify legacy database row with raw 'clinical_reviewer' string is transparently read and serialized as 'document_reviewer'
    db_legacy = factory()
    try:
        from sqlalchemy import text as sql_text
        from app.schemas.tenant import MembershipAssignInput

        # Input schema accepts legacy 'clinical_reviewer' and normalizes to DOCUMENT_REVIEWER
        parsed_input = MembershipAssignInput(user_id=role_users[OrganizationRole.DOCUMENT_REVIEWER], role="clinical_reviewer")  # type: ignore[arg-type]
        assert parsed_input.role is OrganizationRole.DOCUMENT_REVIEWER
        assert parsed_input.role.value == "document_reviewer"

        db_legacy.execute(
            sql_text("UPDATE organization_memberships SET role = 'clinical_reviewer' WHERE user_id = :uid"),
            {"uid": role_users[OrganizationRole.DOCUMENT_REVIEWER]},
        )
        db_legacy.commit()
    finally:
        db_legacy.close()

    with TestClient(app, base_url="http://127.0.0.1:8000") as legacy_client:
        _, legacy_csrf = _login_user_via_bff(
            legacy_client,
            idp,
            sub=f"sub-{OrganizationRole.DOCUMENT_REVIEWER.value}",
            email=f"{OrganizationRole.DOCUMENT_REVIEWER.value}@jyxia.local",
            code="c-legacy-rev",
        )
        assert legacy_client.get("/api/v1/me/organizations").json()["organizations"][0]["role"] == "document_reviewer"
        assert legacy_client.get(f"/api/v1/organizations/{org_a.id}/access-context").json()["role"] == "document_reviewer"
        assert legacy_client.get(f"/api/v1/organizations/{org_a.id}/cases").json()["role"] == "document_reviewer"
        sel_legacy = legacy_client.post(
            "/api/v1/auth/select-organization",
            json={"organization_id": org_a.id},
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: legacy_csrf},
        )
        assert sel_legacy.status_code == 200
        assert sel_legacy.json()["role"] == "document_reviewer"

    with TestClient(app, base_url="http://127.0.0.1:8000") as admin_check_client:
        _login_user_via_bff(
            admin_check_client,
            idp,
            sub=f"sub-{OrganizationRole.ORG_ADMIN.value}",
            email=f"{OrganizationRole.ORG_ADMIN.value}@jyxia.local",
            code="c-admin-legacy-check",
        )
        members_list = admin_check_client.get(f"/api/v1/organizations/{org_a.id}/members").json()["members"]
        rev_entries = [m for m in members_list if m["user_id"] == role_users[OrganizationRole.DOCUMENT_REVIEWER]]
        assert len(rev_entries) == 1
        assert rev_entries[0]["role"] == "document_reviewer"

    # 2. Multi-organization user selection, session/CSRF rotation & mid-session membership revocation
    with TestClient(app, base_url="http://127.0.0.1:8000") as multi_client:
        sess_multi_initial, csrf_multi = _login_user_via_bff(
            multi_client, idp, sub="sub-multi", email="multi@jyxia.local", code="c-multi"
        )
        initial_sess_id = multi_client.get("/api/v1/auth/session").json()["session_id"]
        orgs_resp = multi_client.get("/api/v1/me/organizations")
        assert orgs_resp.status_code == 200
        assert len(orgs_resp.json()["organizations"]) == 2
        assert orgs_resp.json()["active_organization_id"] is None

        # Must select active org before querying org endpoint
        assert multi_client.get(f"/api/v1/organizations/{org_a.id}/cases").status_code == 403

        # Cannot switch to arbitrary unknown org (and failed switch does not rotate valid session)
        assert (
            multi_client.post(
                "/api/v1/auth/select-organization",
                json={"organization_id": "non-existent-org"},
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_multi},
            ).status_code
            == 403
        )

        # Select org_b (ORG_ADMIN) -> rotates session + CSRF tokens and revokes previous session!
        sel_b = multi_client.post(
            "/api/v1/auth/select-organization",
            json={"organization_id": org_b.id},
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_multi},
        )
        assert sel_b.status_code == 200
        assert sel_b.json()["role"] == "org_admin"
        sess_after_b = sel_b.cookies.get(SESSION_COOKIE_NAME)
        csrf_after_b = sel_b.cookies.get(CSRF_COOKIE_NAME)
        assert sess_after_b and csrf_after_b
        assert sess_after_b != sess_multi_initial
        assert csrf_after_b != csrf_multi

        rotated_sess_info = multi_client.get("/api/v1/auth/session").json()
        assert rotated_sess_info["session_id"] != initial_sess_id
        assert rotated_sess_info["active_organization_id"] == org_b.id

        # Previous session token MUST be rejected immediately with 401 after organization switch!
        with TestClient(app, base_url="http://127.0.0.1:8000") as stale_token_client:
            stale_token_client.cookies.set(
                SESSION_COOKIE_NAME, sess_multi_initial, domain="127.0.0.1", path="/"
            )
            assert stale_token_client.get("/api/v1/me").status_code == 401
            assert stale_token_client.get(f"/api/v1/organizations/{org_b.id}/cases").status_code == 401

        # Previous CSRF token MUST be rejected with 403 even when paired with new session cookie!
        assert (
            multi_client.post(
                "/api/v1/auth/select-organization",
                json={"organization_id": org_a.id},
                headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_multi},
            ).status_code
            == 403
        )

        assert multi_client.get(f"/api/v1/organizations/{org_b.id}/cases").json()["cases"][0]["case_code"] == "CASE-B-001"
        assert multi_client.get(f"/api/v1/organizations/{org_a.id}/cases").status_code == 403

        # Select org_a (READ_ONLY) using new rotated CSRF token -> succeeds and rotates again; then suspend membership -> 403!
        sel_a = multi_client.post(
            "/api/v1/auth/select-organization",
            json={"organization_id": org_a.id},
            headers={"Origin": "http://127.0.0.1:8000", CSRF_HEADER_NAME: csrf_after_b},
        )
        assert sel_a.status_code == 200
        assert sel_a.cookies.get(SESSION_COOKIE_NAME) != sess_after_b
        assert sel_a.cookies.get(CSRF_COOKIE_NAME) != csrf_after_b
        assert multi_client.get(f"/api/v1/organizations/{org_a.id}/members").status_code == 403

        db_revoke = factory()
        try:
            m_a_row = db_revoke.get(type(m_a), m_a.id)
            assert m_a_row is not None
            m_a_row.status = MembershipStatus.SUSPENDED.value
            db_revoke.commit()
        finally:
            db_revoke.close()

        assert multi_client.get(f"/api/v1/organizations/{org_a.id}/cases").status_code == 403

    # Verify BOTH tenant audit chain & global security audit chain remained linear & tamper-free
    verify_db = factory()
    try:
        assert AuditEventRepository.verify_chain(verify_db, TenantContext(organization_id=org_a.id))
        assert AuditEventRepository.verify_chain(verify_db, TenantContext(organization_id=org_b.id))
        assert SecurityAuditRepository.verify_chain(verify_db)
        denied_count = sum(
            1
            for ev in verify_db.scalars(select(SecurityAuditEvent))
            if ev.outcome == "denied"
        )
        assert denied_count >= 10
    finally:
        verify_db.close()
