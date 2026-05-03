# Sprint 2 Phase 4 — Vertical-slice runbook

**Audience:** the Lehen maintainer running Sprint 2's first end-to-end test, plus an AI assistant (Claude on web) helping interpret Microsoft / Keycloak UI screens, debug error responses, and suggest fixes when the run hits friction.

This document is **self-contained**. The web AI assistant will not see the Lehen codebase; everything it needs to reason about the test is below.

---

## 1. What Lehen is (in one paragraph)

Lehen is an open-source on-premise platform that captures organizational knowledge as a side effect of normal work across mail, Teams, and ITSM. Two processes: a **Hub** (Python/FastAPI server, runs on-premise) and an **Edge** (Tauri v2 + React desktop app, runs as a user-permission Windows app). Users sign into the Edge via SSO (Keycloak or Microsoft Entra), see integration instances their role authorizes, and click Connect to grant Lehen delegated access to a source (e.g., their Outlook mailbox via Microsoft Graph).

The current sprint's task is the first end-to-end run: Edge → Hub → real Microsoft Entra OIDC for sign-in → real Microsoft Graph OAuth for `outlook-graph` data access. Until this sprint, every component had unit-level coverage; this is the first time the parts are being exercised together against real Microsoft endpoints.

---

## 2. What "done" looks like

A test run is successful when, against a real Microsoft 365 Developer tenant and a local Hub:

1. The Hub starts cleanly, configured for Entra as the SIAM identity provider.
2. The Edge launches via `npm run tauri:dev`, fetches the Hub's `/auth/public-config`, and presents a "Sign in with Microsoft Entra" button.
3. Clicking the button opens the system browser to a Microsoft login page.
4. After successful Microsoft login, the browser redirects to `lehen://auth/callback?code=…&state=…`. The Edge picks up the URL via the registered custom URL scheme.
5. The Edge exchanges the code for an access token at Microsoft's token endpoint, stores it in the Windows Credential Manager, and calls the Hub's `/me` endpoint with the token as a bearer.
6. `/me` returns the list of integration instances the user's Entra app role is mapped to. At minimum, the test user has an `outlook-graph` instance visible.
7. Clicking **Connect** on the `outlook-graph` row triggers a second OAuth flow — this time the Edge calls the Hub's `/me/connections/{id}/initiate`, gets back a Microsoft Graph authorization URL, and opens it in the system browser.
8. The user consents in Microsoft to the Graph scopes (`Mail.Read`, `User.Read`, `offline_access`, `openid`, `profile`, `email`).
9. The browser redirects to `lehen://oauth/callback?code=…&state=…`. The Edge picks up the URL and posts `{code, state}` to the Hub's `/me/connections/{id}/complete`.
10. The Hub exchanges the code for tokens at Microsoft's token endpoint, calls Graph `/me` to extract the user's email and display name, persists the tokens encrypted-at-rest in ArcadeDB, and returns the new connection record.
11. The Edge refreshes its `/me` view; the `outlook-graph` instance now shows status `connected` with the user's mailbox label.

That's the full slice. No mail content is read — the slice is "the connection plumbing all the way through," not the capture loop.

---

## 3. Prerequisites — what the operator needs to have or set up

### 3.1 Microsoft 365 Developer tenant (free, ~30 minutes)

* Sign up at [developer.microsoft.com/microsoft-365/dev-program](https://developer.microsoft.com/microsoft-365/dev-program).
* Choose "Instant sandbox" — you get a tenant pre-seeded with sample users (`MeganB@yourtenant.onmicrosoft.com` etc.).
* You become a Global Admin in this tenant. Note the tenant id (a GUID); you'll need it.

### 3.2 Microsoft Entra application registration (~15 minutes)

In the Entra admin center for your dev tenant, register one app that does double duty: it's both the SIAM identity provider for Lehen sign-in **and** the OAuth client for `outlook-graph` source access.

* **Name:** `lehen-hub-dev` (or any name).
* **Supported account types:** Accounts in this organizational directory only (single tenant).
* **Redirect URI:** add as type **"Public client/native (mobile & desktop)"** with value `lehen://oauth/callback`.
* Add a second redirect URI on the same app, also "Public client/native": `lehen://auth/callback` (for SIAM sign-in).
* Under **Certificates & secrets**, create a client secret. **Copy the secret value the moment it's shown — you cannot retrieve it later.**
* Under **Expose an API**, set the Application ID URI to the default `api://{client-id}`. Add a scope `access_as_user`.
* Under **App roles**, add an app role:
  * Display name: `Lehen Admin`
  * Allowed member types: Users/Groups
  * Value: `lehen-admin`
  * Description: `Maps to lehen-admin in the Hub's SIAM mapping`
* Under **API permissions** (for the Microsoft Graph scopes the source adapter requests), add **delegated** permissions:
  * `openid`, `profile`, `email`, `offline_access`
  * `User.Read`, `Mail.Read`
* Click "Grant admin consent for {your tenant}" so users don't see consent prompts for the standard scopes.
* Under **Enterprise applications → your app → Users and groups**, assign at least one test user (e.g., `MeganB`) to the `Lehen Admin` app role.

### 3.3 Keycloak (optional for this slice — Entra is enough)

Phase 4 only requires Entra to be working; Keycloak does not need to be set up unless the operator wants to verify provider-switching also works. If keeping it simple, skip Keycloak for now.

### 3.4 Local toolchain

* Python 3.12 with `uv` installed (Hub dependency manager).
* Docker Desktop (for ArcadeDB).
* Node.js 20+ and npm 10+ (Edge dependency manager).
* Rust 1.85+ (Edge backend).
* On Windows: WebView2 runtime (preinstalled on Windows 11).

### 3.5 Secrets to generate

```bash
python -c "import secrets, base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
```

Run this **three times**. You'll need:

* `LEHEN_CRYPTO__MASTER_KEY` (32 url-safe-base64 bytes)
* `LEHEN_CRYPTO__AUDIT_PEPPER` (32 url-safe-base64 bytes)
* `LEHEN_LOCAL_ADMIN__SIGNING_KEY` (32 url-safe-base64 bytes)

---

## 4. Configuration

Create `hub/.env` with these values (no leading/trailing whitespace, no quotes):

```
LEHEN_ARCADEDB__HOST=localhost
LEHEN_ARCADEDB__HTTP_PORT=2480
LEHEN_ARCADEDB__USER=root
LEHEN_ARCADEDB__PASSWORD=arcade-dev-pw
LEHEN_ARCADEDB__DATABASE=lehen

LEHEN_CRYPTO__MASTER_KEY=<first generated value>
LEHEN_CRYPTO__AUDIT_PEPPER=<second generated value>

LEHEN_IDENTITY_PROVIDER=entra
LEHEN_ENTRA__TENANT_ID=<your tenant id GUID>
LEHEN_ENTRA__AUDIENCE=api://<your client id>
LEHEN_ENTRA__ADMIN_ROLE=lehen-admin
LEHEN_ENTRA__EDGE_CLIENT_ID=<your client id>
LEHEN_ENTRA__ADMIN_UI_CLIENT_ID=<your client id>

LEHEN_LOCAL_ADMIN__ENABLED=true
LEHEN_LOCAL_ADMIN__SIGNING_KEY=<third generated value>
```

The same `client_id` is used three times because the dev app does triple duty (SIAM sign-in for Edge, SIAM sign-in for admin UI, and `outlook-graph` source OAuth client). In production these would typically be separate apps.

---

## 5. The runbook itself

### Step 1 — boot ArcadeDB

```bash
docker run -d --name arcadedb \
  -p 2480:2480 \
  -e JAVA_OPTS="-Darcadedb.server.rootPassword=arcade-dev-pw" \
  arcadedata/arcadedb:latest
```

Verify: `curl http://localhost:2480/api/v1/server` returns JSON.

### Step 2 — boot the Hub

```bash
cd hub
uv sync
uv run python -m lehen_hub.cli create-admin --username admin
# Copy the printed password somewhere safe.
uv run uvicorn lehen_hub.main:app --reload
```

Verify: `curl http://localhost:8000/health/ready` returns `{"status":"ok",…}` with both `arcadedb` and `entra` checks ok. The `entra` check makes a live HTTPS call to Microsoft's well-known endpoint — if it's failing, your `LEHEN_ENTRA__TENANT_ID` is wrong.

### Step 3 — log into the Hub admin UI as the bootstrap admin

Open `http://localhost:8000/admin/` in a browser. The admin SPA should load, prompt for username + password, and accept the bootstrap credentials from Step 2.

> **Note on first SSO admin login:** the moment you log in successfully via SSO with the `lehen-admin` Entra app role, the Hub auto-disables the local-admin account. To re-enable for emergencies, re-run the CLI. For Phase 4, **don't worry about this yet — log in as the local admin first** to set up the SIAM mapping and integration instance, then test SSO.

### Step 4 — configure the SIAM mapping in the admin UI

In the admin UI's SIAM section, create a mapping:

```
lehen-admin: ["outlook-graph-prod"]
```

This says: any user whose JWT carries the `lehen-admin` role is authorized to connect to the `outlook-graph-prod` integration instance.

### Step 5 — create the `outlook-graph` integration instance

In the admin UI's Integrations section, create:

* **ID:** `outlook-graph-prod`
* **Type:** `outlook-graph`
* **Display name:** `Outlook (Graph) — dev tenant`
* **tenant_id:** your Entra tenant GUID
* **client_id:** your Entra app client id
* **client_secret:** the secret value you copied during app registration
* **Enabled:** true
* **Multi-connection allowed:** true

The Hub encrypts the `client_secret` at rest with the master key.

### Step 6 — boot the Edge in dev mode

```bash
cd edge
npm install
npm run tauri:dev
```

Wait for the Tauri window to open (first invocation takes a few minutes for Rust deps; subsequent runs are fast).

### Step 7 — sign in via Entra

In the Edge window:

1. Verify the boot screen says it's pointing at `http://localhost:8000` and that the SIAM provider shows as `Microsoft Entra`.
2. Click **Sign in with Microsoft Entra**.
3. The system browser opens to `login.microsoftonline.com` with your tenant.
4. Log in as the test user you assigned the `lehen-admin` app role to.
5. The browser redirects to `lehen://auth/callback?…`. The Edge should come to the foreground and now show the integration list.

### Step 8 — connect outlook-graph

In the Edge:

1. The list should show one row: `Outlook (Graph) — dev tenant`, status `needs_connect`.
2. Click **Connect**.
3. The system browser opens to a Microsoft consent screen for Mail.Read + User.Read.
4. Consent. The browser redirects to `lehen://oauth/callback?…`.
5. The Edge picks up the URL, posts to the Hub's `/complete` endpoint, and refreshes.
6. The row should now show status `connected` with your mailbox display label.

### Step 9 — verify in the Hub admin UI

Switch back to the admin UI:

* `IntegrationConnection` for the test user should show `status="connected"`, `external_subject` populated with their SMTP address, `display_label` populated, `encrypted_credentials` non-null, `last_health_status="ok"`.
* `ConsentEvent` should have a row with `action="granted"` for the test user.

### Step 10 — verify the admin-revoke cascade

In the admin UI:

1. Disable the `outlook-graph-prod` instance.
2. Reload the Edge (or wait for next `/me` poll).
3. The integration row should now show a revoked-by-admin annotation (status `revoked-by-admin`) — the user understands what happened without having to ask the admin.
4. In the Hub admin UI, the connection row should be `status="disconnected"`, `encrypted_credentials=null`, with a second `ConsentEvent` recording `action="revoked-by-admin-disable"`.

That's the slice.

---

## 6. Likely failure modes and how to triage

These are the things most likely to bite, in rough order of probability.

### "AADSTS50011: redirect URI mismatch"
The Entra app does not have `lehen://oauth/callback` (or `lehen://auth/callback`) registered as a public-client redirect URI. Add it. Make sure both schemes are listed. Note that Entra distinguishes between "Web", "SPA", and "Public client/native" redirect types — desktop URL schemes go in the **public-client/native** list.

### "AADSTS65001: consent has not been granted"
Either the user has not been assigned the app role, or admin consent has not been granted for the requested scopes. Re-grant admin consent on the API permissions page; reassign the user to the app role under "Users and groups."

### Edge does not pick up the deep-link callback
Two common causes:
* On Windows, the `lehen://` scheme registration only takes effect after the Tauri app has been launched at least once. In dev mode, run `tauri:dev`, close it, and run again — registration happens during launch.
* The browser is showing the callback URL as text rather than triggering the OS handler. Check that the system associates `lehen://` with `lehen-edge.exe` (Windows registry: `HKEY_CLASSES_ROOT\lehen`).

### "invalid_grant" on token exchange
Three common causes:
* Wrong `client_secret` in the integration instance config — re-paste, watch for trailing whitespace.
* Code already used (Microsoft auth codes are single-use). The Edge UI got into a state where it tried to complete twice.
* `redirect_uri` mismatch between the auth request and the token exchange. The Hub embeds the redirect URI in the OAuth state; this should not happen unless the state was tampered with.

### Hub /health/ready shows entra check as "fail"
The Hub is making a live HTTPS call to `https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration`. If this fails:
* Wrong tenant id.
* No outbound HTTPS from the Hub host (firewall, proxy).
* Microsoft is having an outage (rare).

### `/me` returns empty integrations
The user's JWT carries the `lehen-admin` role (verifiable by decoding the token at jwt.io with verification disabled), but the SIAM mapping does not authorize it for the `outlook-graph-prod` instance. Check the SIAM mapping in the admin UI.

### Connection appears in /me as "stale" without ever working
The token refresh failed. Most often: the Microsoft Graph scopes do not include `offline_access`, so no refresh_token was issued, so the first expiry-driven refresh fails. Verify the scope list in the source adapter (the Hub requests `offline_access` automatically — check the auth URL in the browser address bar to confirm).

---

## 7. What this slice does NOT cover

For clarity — these are deliberately out of scope for Phase 4 and will land in later sprints:

* Reading actual mail content from Graph (Sprint 3+).
* The privacy filter that strips raw content before any data leaves Edge (Sprint 3+).
* Multiple mailboxes per user (`Mail.Read.Shared`, the picker UX — Sprint 3 Layer 2).
* Slack, Teams, ServiceNow adapters (Sprint 3+ each).
* `outlook-edge-com` (the COM-based Outlook adapter on the Edge — separate sprint).
* Code-signing the Edge MSI installer (separate productisation track).
* Multi-IdP simultaneously in the same Hub (currently one active provider per deployment).

The slice ends at "the OAuth tokens exist, encrypted at rest, and Graph confirms the user's identity."

---

## 8. What to ask the AI assistant

Useful prompts when stuck:

* "I'm at Step N of the Lehen Phase 4 runbook. I see this error: …. What does this mean and how do I fix it?"
* "Microsoft is showing me {screen description}. What option should I pick?"
* "The Hub log shows: …. Which step in the OAuth flow is this?"
* "How do I decode this JWT to verify the role claim is present?" (Use [jwt.io](https://jwt.io); paste the token, look at the payload.)
* "The /health/ready endpoint shows {response}. What should I check next?"

Less useful:

* "Why doesn't this work?" without context.
* "Show me the code for X" — the assistant cannot see the codebase.

---

## 9. Where to find more detail

* `docs/sprint2_design.md` — full architectural rationale for everything in this slice.
* `docs/dev-setup.md` — operator-side setup instructions for both Keycloak and Entra.
* `docs/admin-bootstrap.md` — local-admin lifecycle and break-glass procedure.
* `DESIGN.md` §10 — the decisions log explaining why each piece is the way it is.
* `docs/backlog.md` — known deferred work and the conditions under which it gets pulled in.

If something doesn't match this runbook, the design docs are authoritative on intent and the code is authoritative on behavior.
