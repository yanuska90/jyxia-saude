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
    resp.raise_for_status()
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
    if resp.status_code not in {201, 204}:
        raise RuntimeError(f"Failed creating user {username}: {resp.status_code} {resp.text}")
    loc = resp.headers.get("location", "")
    if loc and "/" in loc:
        return loc.rstrip("/").rsplit("/", 1)[-1]
    lookup = client.get(
        f"{admin_realm}/users", params={"username": username, "exact": "true"}, headers=headers
    )
    lookup.raise_for_status()
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
        clients_resp.raise_for_status()
        mfa_client = clients_resp.json()[0]
        mfa_client["secret"] = mfa_client_secret
        put_res = client.put(
            f"{admin_realm}/clients/{mfa_client['id']}", json=mfa_client, headers=headers
        )
        put_res.raise_for_status()

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
        flow_create.raise_for_status()
        exec_add = client.post(
            f"{admin_realm}/authentication/flows/{pwd_flow_alias}/executions/execution",
            json={"provider": "auth-username-password-form"},
            headers=headers,
        )
        exec_add.raise_for_status()
        execs = client.get(
            f"{admin_realm}/authentication/flows/{pwd_flow_alias}/executions", headers=headers
        )
        execs.raise_for_status()
        first_exec = execs.json()[0]
        first_exec["requirement"] = "REQUIRED"
        client.put(
            f"{admin_realm}/authentication/flows/{pwd_flow_alias}/executions",
            json=first_exec,
            headers=headers,
        ).raise_for_status()

        all_flows = client.get(f"{admin_realm}/authentication/flows", headers=headers)
        all_flows.raise_for_status()
        pwd_flow_id = next(f["id"] for f in all_flows.json() if f["alias"] == pwd_flow_alias)

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
            "protocolMappers": mfa_client.get("protocolMappers", []),
        }
        client.post(f"{admin_realm}/clients", json=pwd_client_payload, headers=headers).raise_for_status()

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
