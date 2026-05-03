# Dev environment setup

This document walks a fresh contributor through everything needed to run the Hub locally with both supported SIAM identity providers (Keycloak and Entra) plus the local-admin bootstrap path. Reproducible on a fresh laptop in about an hour, half of which is provider provisioning that runs unattended.

The Hub does not ship secrets in this repo. Each section ends with the env vars to set in a local `.env` file (which is git-ignored).

## Prerequisites

- Python 3.12 with `uv` installed
- Docker Desktop (for ArcadeDB and Keycloak)
- A web browser (for the Microsoft and Keycloak admin consoles)

## 1. ArcadeDB

The Hub needs an ArcadeDB instance reachable at `arcadedb:2480` (the default container hostname when run alongside the Hub via `docker compose`). For solo dev, `localhost:2480` works if you adjust `LEHEN_ARCADEDB__HOST`.

```bash
docker run -d --name arcadedb \
  -p 2480:2480 \
  -e JAVA_OPTS="-Darcadedb.server.rootPassword=arcade-dev-pw" \
  arcadedata/arcadedb:latest
```

Env vars:

```
LEHEN_ARCADEDB__HOST=localhost
LEHEN_ARCADEDB__HTTP_PORT=2480
LEHEN_ARCADEDB__USER=root
LEHEN_ARCADEDB__PASSWORD=arcade-dev-pw
LEHEN_ARCADEDB__DATABASE=lehen
```

## 2. Crypto keys

The Hub needs two 32-byte url-safe-base64 keys: one for at-rest secret encryption (`master_key`) and one for HMAC fingerprinting in the audit log (`audit_pepper`). Generate with:

```bash
python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Run twice, paste each output once:

```
LEHEN_CRYPTO__MASTER_KEY=<first 32-byte url-safe-base64>
LEHEN_CRYPTO__AUDIT_PEPPER=<second 32-byte url-safe-base64>
```

These keys are tied to the database. If you wipe the DB, regenerate. If you lose them, every encrypted secret in the DB becomes unreadable — that's the design.

## 3. Identity provider — pick one or set up both

The Hub runs with exactly one active SIAM IdP per deployment, selected by `LEHEN_IDENTITY_PROVIDER=keycloak | entra`. In dev you can populate both blocks and switch by changing the selector and restarting.

### 3a. Keycloak (default for OSS-shop deployments)

Run a local Keycloak in dev mode:

```bash
docker run -d --name keycloak \
  -p 8080:8080 \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:latest start-dev
```

In the Keycloak admin console at `http://localhost:8080`:

1. Create a realm named `lehen`.
2. Create realm roles: `lehen-admin`, plus any user roles your SIAM mapping uses (e.g. `change-manager`).
3. Create two public OIDC clients:
   - `lehen-edge` (used by the Edge for OIDC PKCE)
   - `lehen-admin-ui` (used by the admin SPA for OIDC PKCE)
   - For both: client authentication off, standard flow on, valid redirect URIs include `lehen://oauth/callback` and `http://localhost:8000/admin/*`.
4. Create one confidential client `lehen-hub` with audience mapping that puts `lehen-hub` in the `aud` claim (Keycloak: client → Client Scopes → audience mapper).
5. Create at least one test user, assign realm roles `lehen-admin` and (optionally) a user role.

Env vars:

```
LEHEN_IDENTITY_PROVIDER=keycloak
LEHEN_KEYCLOAK__BASE_URL=http://localhost:8080
LEHEN_KEYCLOAK__REALM=lehen
LEHEN_KEYCLOAK__AUDIENCE=lehen-hub
LEHEN_KEYCLOAK__ADMIN_ROLE=lehen-admin
LEHEN_KEYCLOAK__EDGE_CLIENT_ID=lehen-edge
LEHEN_KEYCLOAK__ADMIN_UI_CLIENT_ID=lehen-admin-ui
```

A realm export ready for one-click import lives at `ops/keycloak/lehen-realm.json` once Sprint 1.5 ships the export. Until then, follow the steps above.

### 3b. Entra (default for M365-shop deployments)

If you don't already have a Microsoft 365 tenant you can register apps in, sign up for the **Microsoft 365 Developer Program** at https://developer.microsoft.com/microsoft-365/dev-program. Pick "Instant Sandbox" — it provisions a tenant pre-seeded with sample users in about ten minutes.

In the Entra admin center for your dev tenant:

1. **App registrations → New registration.**
   - Name: `lehen-hub-dev`.
   - Supported account types: single-tenant (your dev tenant only).
   - Redirect URI: type `Public client/native`, value `lehen://oauth/callback`.
2. **Expose an API.**
   - Set Application ID URI to `api://{client-id}` (the default).
   - Add scope `access_as_user` with admin-and-user consent.
3. **App roles.**
   - Add `lehen-admin` (allowed member types: Users/Groups). Add any other user roles your SIAM mapping uses.
4. **Enterprise applications → your app → Users and groups.**
   - Assign at least one test user to the `lehen-admin` role.
5. **Certificates & secrets.**
   - Create a client secret only if you also want to use the same app for `outlook-graph` / `teams-graph` source-side OAuth (Sprint 2). For the IdentityProvider path alone, no secret is needed (PKCE).
6. **API permissions.**
   - Sprint 1.5: `openid`, `profile`, `email`. Sprint 2 will add `Mail.Read`, `User.Read`, etc. — see `docs/sprint2_design.md`.

Note your tenant id and client id. Env vars:

```
LEHEN_IDENTITY_PROVIDER=entra
LEHEN_ENTRA__TENANT_ID=<your-tenant-id-guid>
LEHEN_ENTRA__AUDIENCE=api://<your-client-id>
LEHEN_ENTRA__ADMIN_ROLE=lehen-admin
LEHEN_ENTRA__EDGE_CLIENT_ID=<your-client-id>
LEHEN_ENTRA__ADMIN_UI_CLIENT_ID=<your-client-id>
```

## 4. Local-admin bootstrap path (optional but recommended for dev)

The local-admin path lets you log into the admin UI before SIAM is configured, and provides a break-glass channel if SIAM breaks. It is auto-disabled on the first successful SIAM admin login.

Generate a 32-byte url-safe-base64 signing key (separate from the crypto keys above):

```bash
python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Env vars:

```
LEHEN_LOCAL_ADMIN__ENABLED=true
LEHEN_LOCAL_ADMIN__SIGNING_KEY=<32-byte url-safe-base64>
```

After the Hub is configured and ArcadeDB is reachable, create the bootstrap admin password:

```bash
cd hub
uv run python -m lehen_hub.cli create-admin --username admin
```

The CLI prints the generated password once. Save it somewhere safe — re-running invalidates it. See `docs/admin-bootstrap.md` for the operator-facing procedure.

## 5. Run the Hub

```bash
cd hub
uv sync
uv run uvicorn lehen_hub.main:app --reload
```

The Hub binds to `http://localhost:8000` by default. Smoke-test:

- `GET /health/live` → `{"status": "ok"}`
- `GET /health/ready` → checks ArcadeDB and the configured IdP's well-known endpoint
- `GET /auth/public-config` → returns the active provider's discovery payload (the Edge calls this)
- `POST /admin/local-login` with `{"username": "admin", "password": "<bootstrap pw>"}` → returns a Hub-self-issued JWT scoped to admin

## 6. Run the tests

```bash
cd hub
uv run pytest
```

138 tests should pass with no live external dependencies — all SIAM, JWKS, and ArcadeDB calls are mocked.

## Switching SIAM providers in dev

Both blocks (`LEHEN_KEYCLOAK__*` and `LEHEN_ENTRA__*`) can be populated simultaneously. Switch the active provider by changing only `LEHEN_IDENTITY_PROVIDER` and restarting the Hub. The Edge and admin SPA discover the active provider via `GET /auth/public-config` — no client-side rebuild needed.
