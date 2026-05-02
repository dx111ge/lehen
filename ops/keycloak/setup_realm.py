#!/usr/bin/env python3
"""Idempotent Lehen Keycloak realm provisioner.

Provisions the realm, roles, users, OIDC clients, and audience client-scope
that Journey 1 of Lehen needs to run end-to-end. Safe to re-run: every
resource is checked-then-created; existing items are reused as-is.

What gets created in the configured Keycloak server:

* Realm ``lehen`` (or whatever ``--realm`` is set to)
* Realm roles: ``lehen-admin``, ``change-manager``, ``service-desk``
* Users (password ``test1234`` — change for production; this is dev-only):
  - ``dx-admin``      with role ``lehen-admin``
  - ``cm-test``       with role ``change-manager``
  - ``sd-test``       with role ``service-desk``
  - ``multi-test``    with BOTH ``change-manager`` and ``service-desk``
                      (verifies the multi-role union behavior of /me)
* Audience-only OIDC client ``lehen-hub`` (bearer-only; identifies the Hub
  as a resource server)
* Public PKCE-only OIDC client ``lehen-edge`` (used by the user SPA at
  ``/app/`` and, later, the Tauri Edge)
* Public PKCE-only OIDC client ``lehen-admin-ui`` (used by the admin SPA
  at ``/admin/``)
* Client scope ``lehen-hub-audience`` with an OIDC audience-mapper for
  ``lehen-hub``, attached as a default scope to the two public clients.
  This makes every access token issued via ``lehen-edge`` /
  ``lehen-admin-ui`` carry ``"aud": [..., "lehen-hub"]``, which the Hub's
  JWT validator requires.

Direct Access Grants (ROPC) is enabled on ``lehen-edge`` so a curl-based
journey verification can mint tokens with username+password. Disable
``directAccessGrantsEnabled`` in production realms.

Configuration via env vars (or command-line overrides):

* ``KEYCLOAK_BASE_URL``       — required, no default
* ``KEYCLOAK_ADMIN_USER``     — default ``admin`` (Keycloak's stock default)
* ``KEYCLOAK_ADMIN_PASSWORD`` — required, no default
* ``KEYCLOAK_ADMIN_REALM``    — default ``master`` (the realm where the
                                admin token is minted, NOT the Lehen realm)

Run with stdlib only — no third-party deps:

    $env:KEYCLOAK_BASE_URL = "http://your-keycloak-host:8180"
    $env:KEYCLOAK_ADMIN_PASSWORD = "..."
    python ops/keycloak/setup_realm.py
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any

DEFAULTS = {
    "base_url": os.environ.get("KEYCLOAK_BASE_URL"),
    "admin_user": os.environ.get("KEYCLOAK_ADMIN_USER", "admin"),
    "admin_realm": os.environ.get("KEYCLOAK_ADMIN_REALM", "master"),
    "lehen_realm": "lehen",
}

# ---- target spec -----------------------------------------------------------

REALM_ROLES: list[str] = ["lehen-admin", "change-manager", "service-desk"]
USER_PASSWORD = "test1234"  # noqa: S105 — dev seed value, documented above

USERS: list[dict[str, Any]] = [
    {"username": "dx-admin", "roles": ["lehen-admin"]},
    {"username": "cm-test", "roles": ["change-manager"]},
    {"username": "sd-test", "roles": ["service-desk"]},
    {"username": "multi-test", "roles": ["change-manager", "service-desk"]},
]

HUB_AUDIENCE = "lehen-hub"
EDGE_CLIENT = "lehen-edge"
ADMIN_UI_CLIENT = "lehen-admin-ui"
HUB_AUDIENCE_SCOPE = "lehen-hub-audience"

EDGE_REDIRECT_URIS = [
    "http://localhost:8000/app/callback.html",
    "http://localhost:8000/app/",
    "http://127.0.0.1:*/callback",
]
ADMIN_UI_REDIRECT_URIS = [
    "http://localhost:8000/admin/callback.html",
    "http://localhost:8000/admin/",
]
WEB_ORIGINS = ["http://localhost:8000", "+"]


# ---- thin Keycloak Admin REST client ---------------------------------------


class KCError(RuntimeError):
    pass


class KC:
    def __init__(self, base_url: str, token: str) -> None:
        self.base = base_url.rstrip("/")
        self.token = token

    def _req(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        accept_404: bool = False,
    ) -> tuple[int, Any, dict[str, str]]:
        url = self.base + path
        data = json.dumps(body).encode("utf-8") if body is not None else None
        headers = {"Authorization": f"Bearer {self.token}"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload_text = resp.read().decode("utf-8") if resp.length != 0 else ""
                resp_headers = dict(resp.headers)
                status = resp.status
        except urllib.error.HTTPError as exc:
            payload_text = exc.read().decode("utf-8", errors="replace")
            status = exc.code
            resp_headers = dict(exc.headers) if exc.headers else {}
            if status == 404 and accept_404:
                return status, None, resp_headers
            if status == 409:
                return status, None, resp_headers
            raise KCError(f"{method} {path} -> {status}: {payload_text[:500]}") from exc
        try:
            payload = json.loads(payload_text) if payload_text else None
        except json.JSONDecodeError:
            payload = payload_text
        return status, payload, resp_headers

    def get(self, path: str, *, accept_404: bool = False) -> Any:
        return self._req("GET", path, accept_404=accept_404)[1]

    def post(
        self,
        path: str,
        body: dict[str, Any] | list[Any],
    ) -> tuple[int, Any, dict[str, str]]:
        return self._req("POST", path, body)  # type: ignore[arg-type]

    def put(self, path: str, body: dict[str, Any] | list[Any]) -> None:
        self._req("PUT", path, body)  # type: ignore[arg-type]

    def delete(self, path: str) -> None:
        self._req("DELETE", path, accept_404=True)


def get_admin_token(base_url: str, admin_realm: str, user: str, password: str) -> str:
    url = (
        f"{base_url.rstrip('/')}/realms/{admin_realm}/protocol/openid-connect/token"
    )
    body = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": user,
            "password": password,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        text = exc.read().decode("utf-8", errors="replace")
        raise KCError(f"admin token request failed: {exc.code} {text[:200]}") from exc
    return str(payload["access_token"])


# ---- provisioning steps ----------------------------------------------------


def ensure_realm(kc: KC, realm: str) -> None:
    existing = kc.get(f"/admin/realms/{realm}", accept_404=True)
    if existing:
        log("realm.exists", realm=realm)
        return
    kc.post(
        "/admin/realms",
        {
            "realm": realm,
            "enabled": True,
            "displayName": "Lehen",
            "registrationAllowed": False,
            "loginWithEmailAllowed": True,
            "duplicateEmailsAllowed": False,
            "bruteForceProtected": True,
            "ssoSessionIdleTimeout": 1800,
            "ssoSessionMaxLifespan": 36000,
        },
    )
    log("realm.created", realm=realm)


def ensure_realm_roles(kc: KC, realm: str, roles: Iterable[str]) -> None:
    existing = {r["name"] for r in (kc.get(f"/admin/realms/{realm}/roles") or [])}
    for role in roles:
        if role in existing:
            log("role.exists", role=role)
            continue
        kc.post(f"/admin/realms/{realm}/roles", {"name": role, "composite": False})
        log("role.created", role=role)


def find_user_id(kc: KC, realm: str, username: str) -> str | None:
    rows = kc.get(f"/admin/realms/{realm}/users?username={username}&exact=true") or []
    for row in rows:
        if row.get("username") == username:
            return str(row["id"])
    return None


def ensure_user(
    kc: KC, realm: str, username: str, password: str, roles: list[str]
) -> str:
    user_id = find_user_id(kc, realm, username)
    user_body_base = {
        "username": username,
        "enabled": True,
        "emailVerified": True,
        # Email is required by Keycloak's "fully set up" check before ROPC works.
        "email": f"{username}@lehen.local",
        "firstName": username,
        "lastName": "Lehen-Test",
        "requiredActions": [],
    }
    if user_id is None:
        body = {
            **user_body_base,
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": False,
                }
            ],
        }
        status, _, headers = kc.post(f"/admin/realms/{realm}/users", body)
        if status == 409:
            user_id = find_user_id(kc, realm, username)
            assert user_id is not None
            log("user.exists_409", username=username)
        else:
            location = headers.get("Location") or headers.get("location") or ""
            user_id = location.rsplit("/", 1)[-1]
            log("user.created", username=username)
    else:
        log("user.exists", username=username)
        # Ensure email + required-actions are aligned and password is documented.
        kc.put(f"/admin/realms/{realm}/users/{user_id}", {**user_body_base, "id": user_id})
        kc.put(
            f"/admin/realms/{realm}/users/{user_id}/reset-password",
            {"type": "password", "value": password, "temporary": False},
        )

    # Assign realm roles
    role_objects = []
    for role in roles:
        role_obj = kc.get(f"/admin/realms/{realm}/roles/{role}")
        role_objects.append(role_obj)
    if role_objects:
        kc.post(
            f"/admin/realms/{realm}/users/{user_id}/role-mappings/realm",
            role_objects,
        )
        log("user.roles_assigned", username=username, roles=roles)

    return str(user_id)


def find_client_internal_id(kc: KC, realm: str, client_id: str) -> str | None:
    rows = (
        kc.get(f"/admin/realms/{realm}/clients?clientId={client_id}") or []
    )
    for row in rows:
        if row.get("clientId") == client_id:
            return str(row["id"])
    return None


def ensure_client(
    kc: KC,
    realm: str,
    client_id: str,
    *,
    public: bool,
    bearer_only: bool = False,
    redirect_uris: list[str] | None = None,
    web_origins: list[str] | None = None,
    direct_access: bool = False,
) -> str:
    internal_id = find_client_internal_id(kc, realm, client_id)
    body: dict[str, Any] = {
        "clientId": client_id,
        "enabled": True,
        "protocol": "openid-connect",
        "publicClient": public,
        "bearerOnly": bearer_only,
        "standardFlowEnabled": not bearer_only,
        "directAccessGrantsEnabled": direct_access,
        "serviceAccountsEnabled": False,
        "implicitFlowEnabled": False,
        "redirectUris": redirect_uris or [],
        "webOrigins": web_origins or [],
        "attributes": {
            "pkce.code.challenge.method": "S256" if public and not bearer_only else "",
            "post.logout.redirect.uris": "+",
        },
    }
    if internal_id is None:
        kc.post(f"/admin/realms/{realm}/clients", body)
        internal_id = find_client_internal_id(kc, realm, client_id)
        log("client.created", client=client_id)
    else:
        body["id"] = internal_id
        kc.put(f"/admin/realms/{realm}/clients/{internal_id}", body)
        log("client.updated", client=client_id)
    assert internal_id is not None
    return internal_id


def find_client_scope_id(kc: KC, realm: str, name: str) -> str | None:
    for s in kc.get(f"/admin/realms/{realm}/client-scopes") or []:
        if s.get("name") == name:
            return str(s["id"])
    return None


def ensure_audience_scope(
    kc: KC, realm: str, scope_name: str, target_audience: str
) -> str:
    scope_id = find_client_scope_id(kc, realm, scope_name)
    if scope_id is None:
        kc.post(
            f"/admin/realms/{realm}/client-scopes",
            {
                "name": scope_name,
                "description": (
                    f"Adds {target_audience} to the access-token aud claim "
                    "so the Lehen Hub accepts these tokens as a resource-server."
                ),
                "protocol": "openid-connect",
                "attributes": {
                    "include.in.token.scope": "true",
                    "display.on.consent.screen": "false",
                },
            },
        )
        scope_id = find_client_scope_id(kc, realm, scope_name)
        log("client_scope.created", scope=scope_name)
    else:
        log("client_scope.exists", scope=scope_name)
    assert scope_id is not None

    # Ensure the audience mapper exists on the scope
    mappers = (
        kc.get(f"/admin/realms/{realm}/client-scopes/{scope_id}/protocol-mappers/models")
        or []
    )
    have_audience_mapper = any(
        m.get("protocolMapper") == "oidc-audience-mapper" for m in mappers
    )
    if not have_audience_mapper:
        kc.post(
            f"/admin/realms/{realm}/client-scopes/{scope_id}/protocol-mappers/models",
            {
                "name": f"audience-{target_audience}",
                "protocol": "openid-connect",
                "protocolMapper": "oidc-audience-mapper",
                "consentRequired": False,
                "config": {
                    "included.client.audience": target_audience,
                    "included.custom.audience": "",
                    "id.token.claim": "false",
                    "access.token.claim": "true",
                },
            },
        )
        log("client_scope.audience_mapper_added", scope=scope_name)
    return scope_id


def attach_default_client_scope(
    kc: KC, realm: str, client_internal_id: str, scope_id: str
) -> None:
    # Idempotent: PUT is upsert
    kc.put(
        f"/admin/realms/{realm}/clients/{client_internal_id}"
        f"/default-client-scopes/{scope_id}",
        {},
    )


# ---- logging --------------------------------------------------------------


def log(event: str, **fields: Any) -> None:
    parts = [event] + [f"{k}={v}" for k, v in fields.items()]
    print(" ".join(parts), file=sys.stdout, flush=True)


# ---- main -----------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision the Lehen Keycloak realm.")
    parser.add_argument("--base-url", default=DEFAULTS["base_url"])
    parser.add_argument("--admin-user", default=DEFAULTS["admin_user"])
    parser.add_argument("--admin-realm", default=DEFAULTS["admin_realm"])
    parser.add_argument("--realm", default=DEFAULTS["lehen_realm"])
    args = parser.parse_args()

    if not args.base_url:
        sys.stderr.write(
            "ERROR: KEYCLOAK_BASE_URL env var (or --base-url) is required.\n"
        )
        return 2

    admin_password = os.environ.get("KEYCLOAK_ADMIN_PASSWORD")
    if not admin_password:
        sys.stderr.write("ERROR: KEYCLOAK_ADMIN_PASSWORD env var is required.\n")
        return 2

    log("auth.start", base_url=args.base_url, admin_user=args.admin_user)
    token = get_admin_token(
        args.base_url, args.admin_realm, args.admin_user, admin_password
    )
    log("auth.ok")
    kc = KC(args.base_url, token)

    ensure_realm(kc, args.realm)
    ensure_realm_roles(kc, args.realm, REALM_ROLES)

    for u in USERS:
        ensure_user(kc, args.realm, u["username"], USER_PASSWORD, u["roles"])

    # Audience-only resource-server client first — needs to exist before the
    # audience scope can reference its name.
    ensure_client(
        kc,
        args.realm,
        HUB_AUDIENCE,
        public=False,
        bearer_only=True,
    )

    edge_internal = ensure_client(
        kc,
        args.realm,
        EDGE_CLIENT,
        public=True,
        redirect_uris=EDGE_REDIRECT_URIS,
        web_origins=WEB_ORIGINS,
        direct_access=True,
    )
    admin_ui_internal = ensure_client(
        kc,
        args.realm,
        ADMIN_UI_CLIENT,
        public=True,
        redirect_uris=ADMIN_UI_REDIRECT_URIS,
        web_origins=WEB_ORIGINS,
    )

    scope_id = ensure_audience_scope(kc, args.realm, HUB_AUDIENCE_SCOPE, HUB_AUDIENCE)

    attach_default_client_scope(kc, args.realm, edge_internal, scope_id)
    attach_default_client_scope(kc, args.realm, admin_ui_internal, scope_id)
    log("audience_scope.attached", clients=[EDGE_CLIENT, ADMIN_UI_CLIENT])

    log("done", realm=args.realm)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
