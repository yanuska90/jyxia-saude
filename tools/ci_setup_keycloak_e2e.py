"""Provision ephemeral Keycloak 26.8.2 test users, TOTP & OIDC clients for CI E2E."""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import time
from typing import Any

import httpx


def _wait_for_keycloak(client: httpx.Client, health_url: str, realm_discovery_url: str) -> None:
    for _ in range(90):
        try:
            r1 = client.get(health_url, timeout=2.0)
            r2 = client.get(realm_discovery_url, timeout=2.0)
            if r1.status_code == 200 and r2.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(2.0)
    raise RuntimeError("Timed out waiting for Keycloak /health/ready and jyxia-dev OIDC discovery.")


def _assert_ok(resp: httpx.Response, *, step: str) -> None:
    if resp.status_code >= 400:
        raise RuntimeError(
            f"Keycloak admin step '{step}' failed: HTTP {resp.status_code}: {resp.text[:500]}"
        )


def _get_admin_token(
    client: httpx.Client, base_url: str, username: str, password: str
) -> str:
    resp = client.post(
        f"{base_url}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": username,
            "password": password,
        },
        timeout=10.0,
    )
    _assert_ok(resp, step="admin_token")
    return str(resp.json()["access_token"])


def _create_user_with_mfa(
    client: httpx.Client,
    admin_realm: str,
    headers: dict[str, str],
    *,
    username: str,
    email: str,
    password: str,
    totp_b32: str,
) -> str:
    payload = {
        "username": username,
        "email": email,
        "emailVerified": True,
        "firstName": "CI",
        "lastName": username,
        "enabled": True,
        "totp": True,
        "requiredActions": [],
        "credentials": [
            {
                "type": "password",
                "value": password,
                "temporary": False,
            },
            {
                "type": "otp",
                "userLabel": "ci-ephemeral-totp",
                "secretData": json.dumps({"value": totp_b32}),
                "credentialData": json.dumps(
                    {
                        "subType": "totp",
                        "digits": 6,
                        "period": 30,
                        "algorithm": "HmacSHA1",
                        "counter": 0,
                        "secretEncoding": "BASE32",
                    }
                ),
            },
        ],
    }
    resp = client.post(f"{admin_realm}/users", json=payload, headers=headers, timeout=10.0)
    _assert_ok(resp, step=f"create_user_{username}")
    loc = resp.headers.get("location", "")
    if loc and "/" in loc:
        return loc.rstrip("/").rsplit("/", 1)[-1]
    lookup = client.get(
        f"{admin_realm}/users", params={"username": username, "exact": "true"}, headers=headers
    )
    _assert_ok(lookup, step=f"lookup_user_{username}")
    return str(lookup.json()[0]["id"])


def main() -> int:
    kc_base = os.environ.get("KC_BASE_URL", "http://127.0.0.1:8080").rstrip("/")
    kc_health = os.environ.get("KC_HEALTH_URL", "http://127.0.0.1:9000/health/ready")
    realm = os.environ.get("KC_REALM", "jyxia-dev")
    admin_user = os.environ["KC_BOOTSTRAP_ADMIN_USERNAME"]
    admin_pass = os.environ["KC_BOOTSTRAP_ADMIN_PASSWORD"]
    github_env_path = os.environ.get("GITHUB_ENV", "")

    realm_issuer = f"{kc_base}/realms/{realm}"
    discovery_url = f"{realm_issuer}/.well-known/openid-configuration"
    admin_realm = f"{kc_base}/admin/realms/{realm}"

    with httpx.Client() as client:
        _wait_for_keycloak(client, kc_health, discovery_url)
        token = _get_admin_token(client, kc_base, admin_user, admin_pass)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

        # Rotate dev client secret to fresh ephemeral CI secret
        mfa_client_secret = f"CiEphemeralOidcSecret_{secrets.token_hex(16)}"
        clients_resp = client.get(
            f"{admin_realm}/clients", params={"clientId": "jyxia-backend-dev"}, headers=headers
        )
        _assert_ok(clients_resp, step="get_mfa_client")
        mfa_clients = clients_resp.json()
        if not mfa_clients:
            raise RuntimeError("Client jyxia-backend-dev not found after realm import.")
        mfa_client = mfa_clients[0]
        mfa_client["secret"] = mfa_client_secret
        redirect_uris = list(mfa_client.get("redirectUris") or [])
        for uri in (
            "http://127.0.0.1:8000/api/v1/auth/callback",
            "http://localhost:8000/api/v1/auth/callback",
            "http://127.0.0.1:8045/api/v1/auth/callback",
            "http://localhost:8045/api/v1/auth/callback",
        ):
            if uri not in redirect_uris:
                redirect_uris.append(uri)
        mfa_client["redirectUris"] = redirect_uris

        web_origins = list(mfa_client.get("webOrigins") or [])
        for origin in (
            "http://127.0.0.1:8000",
            "http://localhost:8000",
            "http://127.0.0.1:8045",
            "http://localhost:8045",
        ):
            if origin not in web_origins:
                web_origins.append(origin)
        mfa_client["webOrigins"] = web_origins

        attrs = dict(mfa_client.get("attributes") or {})
        attrs["post.logout.redirect.uris"] = (
            "http://127.0.0.1:8000/*##http://localhost:8000/*##"
            "http://127.0.0.1:8045/*##http://localhost:8045/*"
        )
        mfa_client["attributes"] = attrs

        put_res = client.put(
            f"{admin_realm}/clients/{mfa_client['id']}", json=mfa_client, headers=headers
        )
        _assert_ok(put_res, step="update_mfa_client_secret")

        # Provision ephemeral password-only browser flow & client to assert MFA fail-closed
        pwd_flow_alias = "ci-ephemeral-pwd-only-browser"
        flow_create = client.post(
            f"{admin_realm}/authentication/flows",
            json={
                "alias": pwd_flow_alias,
                "description": "CI negative-test flow without OTP",
                "providerId": "basic-flow",
                "topLevel": True,
                "builtIn": False,
            },
            headers=headers,
        )
        _assert_ok(flow_create, step="create_pwd_flow")

        exec_add = client.post(
            f"{admin_realm}/authentication/flows/{pwd_flow_alias}/executions/execution",
            json={"provider": "auth-username-password-form"},
            headers=headers,
        )
        _assert_ok(exec_add, step="add_pwd_exec")

        execs = client.get(
            f"{admin_realm}/authentication/flows/{pwd_flow_alias}/executions", headers=headers
        )
        _assert_ok(execs, step="get_pwd_execs")
        first_exec = execs.json()[0]
        first_exec["requirement"] = "REQUIRED"
        put_exec = client.put(
            f"{admin_realm}/authentication/flows/{pwd_flow_alias}/executions",
            json=first_exec,
            headers=headers,
        )
        _assert_ok(put_exec, step="enable_pwd_exec")

        pwd_amr_cfg = client.post(
            f"{admin_realm}/authentication/executions/{first_exec['id']}/config",
            json={
                "alias": "ci-pwd-only-amr-config",
                "config": {
                    "default.reference.value": "pwd",
                    "default.reference.maxAge": "36000",
                },
            },
            headers=headers,
        )
        _assert_ok(pwd_amr_cfg, step="set_pwd_only_amr_config")

        all_flows = client.get(f"{admin_realm}/authentication/flows", headers=headers)
        _assert_ok(all_flows, step="list_flows")
        pwd_flow_id = next(f["id"] for f in all_flows.json() if f["alias"] == pwd_flow_alias)

        cloned_mappers = [
            {k: v for k, v in mapper.items() if k != "id"}
            for mapper in mfa_client.get("protocolMappers", [])
        ]

        pwd_client_id = "jyxia-pwd-only-ci"
        pwd_client_secret = f"CiEphemeralPwdOnly_{secrets.token_hex(16)}"
        pwd_client_payload: dict[str, Any] = {
            "clientId": pwd_client_id,
            "enabled": True,
            "protocol": "openid-connect",
            "publicClient": False,
            "secret": pwd_client_secret,
            "standardFlowEnabled": True,
            "implicitFlowEnabled": False,
            "directAccessGrantsEnabled": False,
            "redirectUris": ["http://127.0.0.1:8000/api/v1/auth/callback"],
            "webOrigins": ["http://127.0.0.1:8000"],
            "attributes": {"pkce.code.challenge.method": "S256"},
            "authenticationFlowBindingOverrides": {"browser": pwd_flow_id},
            "protocolMappers": cloned_mappers,
        }
        client_res = client.post(
            f"{admin_realm}/clients", json=pwd_client_payload, headers=headers
        )
        _assert_ok(client_res, step="create_pwd_only_client")

        # Provision 2 ephemeral test users + RFC 6238 Base32 TOTP credentials
        mfa_username = f"kc_mfa_{secrets.token_hex(4)}"
        mfa_password = f"MfaPass!{secrets.token_hex(12)}"
        mfa_totp_b32 = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
        mfa_sub = _create_user_with_mfa(
            client,
            admin_realm,
            headers,
            username=mfa_username,
            email=f"{mfa_username}@jyxia.local",
            password=mfa_password,
            totp_b32=mfa_totp_b32,
        )

        unbound_username = f"kc_unbound_{secrets.token_hex(4)}"
        unbound_password = f"UnbPass!{secrets.token_hex(12)}"
        unbound_totp_b32 = base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")
        _create_user_with_mfa(
            client,
            admin_realm,
            headers,
            username=unbound_username,
            email=f"{unbound_username}@jyxia.local",
            password=unbound_password,
            totp_b32=unbound_totp_b32,
        )

    env_vars = {
        "JYXIA_KEYCLOAK_E2E_URL": realm_issuer,
        "JYXIA_KEYCLOAK_CLIENT_ID": "jyxia-backend-dev",
        "JYXIA_KEYCLOAK_CLIENT_SECRET": mfa_client_secret,
        "JYXIA_KEYCLOAK_MFA_USER_SUB": mfa_sub,
        "JYXIA_KEYCLOAK_MFA_USERNAME": mfa_username,
        "JYXIA_KEYCLOAK_MFA_PASSWORD": mfa_password,
        "JYXIA_KEYCLOAK_MFA_TOTP_SECRET": mfa_totp_b32,
        "JYXIA_KEYCLOAK_UNBOUND_USERNAME": unbound_username,
        "JYXIA_KEYCLOAK_UNBOUND_PASSWORD": unbound_password,
        "JYXIA_KEYCLOAK_UNBOUND_TOTP_SECRET": unbound_totp_b32,
        "JYXIA_KEYCLOAK_PWD_ONLY_CLIENT_ID": pwd_client_id,
        "JYXIA_KEYCLOAK_PWD_ONLY_CLIENT_SECRET": pwd_client_secret,
    }
    for secret_key in (
        "JYXIA_KEYCLOAK_CLIENT_SECRET",
        "JYXIA_KEYCLOAK_MFA_PASSWORD",
        "JYXIA_KEYCLOAK_MFA_TOTP_SECRET",
        "JYXIA_KEYCLOAK_UNBOUND_PASSWORD",
        "JYXIA_KEYCLOAK_UNBOUND_TOTP_SECRET",
        "JYXIA_KEYCLOAK_PWD_ONLY_CLIENT_SECRET",
    ):
        print(f"::add-mask::{env_vars[secret_key]}")

    if github_env_path:
        with open(github_env_path, "a", encoding="utf-8") as fh:
            for k, v in env_vars.items():
                fh.write(f"{k}={v}\n")
    print(f"Provisioned Keycloak E2E realm={realm} mfa_user={mfa_username} ok=True")
    return 0


if __name__ == "__main__":
    sys.exit(main())
