# Sprint 1.5 — IdentityProvider abstraction + local-admin bootstrap

**Status:** planned, not started
**Sprint shape:** half-sprint, ~5 days
**Predecessor:** Sprint 1 (commit `72eefbd` Lehen v0.1.0 — Hub admin layer + minimal user loop)
**Successor:** Sprint 2 (`docs/sprint2_design.md`) — assumes Sprint 1.5 has shipped

---

## 1. Goal

Land the auth foundation Sprint 2 builds on:

- **Two first-class `IdentityProvider` implementations** (Keycloak, Entra) behind a clean abstraction. Either can be the configured SIAM IdP for a Hub deployment. Both are exercised by tests so the abstraction is provably correct, not paper.
- **A scoped local-admin bootstrap path** that solves the chicken-and-egg of "fresh Hub has no SIAM config and no admin to set it up". Strictly invisible to the Edge surface; valid only on admin endpoints; auto-disables after the first SSO admin login.
- **An Edge-facing config endpoint** (`GET /auth/login-config`) so the Edge talks to the Hub for IdP discovery rather than carrying any IdP knowledge itself.

This sprint exists because folding it into Sprint 2 would mix auth-foundation work with adapter and Edge-bootstrap work — different risk profiles, different debug surfaces. Isolating it makes both sprints clearer.

---

## 2. Predecessor state at sprint start

What Sprint 1 ships:

- JWT validation and JWKS handling in `hub/src/lehen_hub/auth/jwt.py` and `hub/src/lehen_hub/auth/jwks.py`. Currently single-issuer, presumed Keycloak.
- `auth/dependencies.py` — `CurrentUser` resolution from Bearer token.
- `auth/auth_config.py` — issuer/audience configuration.
- Admin bootstrap via environment variables was dropped (commit `d592a7e`). There is no local-admin path in the current code.
- LLMConfig is DB-only (`d592a7e`); SIAM mapping is in DB.

What is **not** in place:

- Any abstraction over the IdP. JWT validation is Keycloak-shaped.
- Any local-auth path on the Hub.
- Any Edge-facing config endpoint.
- No `IdentityProvider` interface implementation in code (the contract exists in DESIGN.md §6 but no concrete code shape).

---

## 3. DESIGN.md decisions to record

Each entry to be added to DESIGN.md §10 with date `2026-05-03`.

### 3.1 Promote Entra `IdentityProvider` from community-contributed to first-class

**Decision:** Ship Entra alongside Keycloak as a first-class `IdentityProvider` implementation. The original DESIGN.md §10 entry calling Entra a community-contributed adapter is superseded by this decision. Other identity providers (Okta, Auth0, Ping, generic SAML) remain community-contributed.

**Reason:** Entra is the most common enterprise IdP, especially in M365 customers — which is the bulk of Lehen's target audience. Building Entra alongside Keycloak now (a) exercises the `IdentityProvider` abstraction at exactly the moment it is formalized, catching design errors immediately, and (b) unblocks the Sprint 2 demo against Microsoft accounts without delaying for an external contributor. Keycloak remains the OSS-shop default; Entra remains the M365-shop default.

### 3.2 Local-admin auth as bootstrap and break-glass path

**Decision:** Hub ships with a strictly scoped local-admin authentication path. The path exists for two situations only: bootstrap (a fresh Hub has no SIAM configured yet) and emergency break-glass (SIAM is broken or admin is locked out).

**Scope rules — load-bearing, must hold under all paths:**

- Single bootstrap admin per Hub install. No multi-admin local accounts.
- Password regenerated on every CLI re-run; the previous password is invalidated. Anyone with shell access on the Hub host can rotate it. This is acceptable because shell access is already root-equivalent in any on-prem deployment.
- Auto-disable on first successful SSO admin login. Re-enabling for an emergency requires the operator to re-run the bootstrap CLI on the Hub host.
- Local-issued JWTs carry `iss: "lehen-hub-local"`, `scope: "admin"`, and a Hub-controlled signing key.
- Local-issued JWTs are valid **only** on `/admin/*` endpoints. The auth dependency on user-facing endpoints rejects them by issuer claim.
- Every local login emits a `LocalAdminLoginEvent` distinct from regular `LoginEvent` so ops can alert on it independently.

**Reason:** A fresh Hub cannot accept SSO until the operator has configured an IdP. Without a local path, the operator has to either pre-seed the database or hardcode IdP config — both bad. A small, explicitly-scoped bootstrap path is the smallest correct solution. The "emergency only" framing is preserved by the auto-disable rule and the heavy audit.

**Trade accepted:** anyone with shell access to the Hub host can authenticate as admin. This is the same authority level as `docker compose down && rm -rf` already grants. The threat model treats Hub host root access as already-compromised; local admin does not weaken it further.

### 3.3 Edge speaks only to Hub for IdP discovery

**Decision:** The Edge does not carry any IdP knowledge. The Edge calls `GET /auth/login-config` on the Hub (the same Hub it already trusts) and receives the active SIAM IdP's OIDC discovery URL, client_id, and required scopes. Edge then runs OIDC PKCE against whichever IdP the Hub names.

**Reason:** Edge architecturally only knows the Hub. Configuring Edge with IdP details directly would make per-customer Hub deployments require per-customer Edge builds. The login-config endpoint is unauthenticated (the user has no token yet) but exposes only what is already public OIDC discovery information.

The local-admin path is **never** returned by `GET /auth/login-config`. Edge has no awareness that local admin exists.

### 3.4 Strict separation of admin and user surfaces

**Decision:** Two completely separate auth surfaces. User surface (Edge → `/me/*`) accepts SIAM-issued JWTs only. Admin surface (browser → `/admin/*`) accepts SIAM-issued JWTs (with admin role claim) or Hub-self-issued JWTs (with `scope: "admin"`). Surfaces share zero auth code paths beyond signature verification.

**Reason:** Confused-deputy risks are the most common authn failures. An explicit cross-surface rejection rule (tested in code) prevents a local-admin JWT from ever being mistakenly accepted on a `/me/*` endpoint, and prevents an Edge-shape user token from being accepted on an `/admin/local-login` endpoint.

---

## 4. External setup

The M365 Developer Program tenant and Entra app registration that Sprint 2 needs for `outlook-graph` are provisioned **here**, in Sprint 1.5, because the same Entra app serves both: SSO (sign-in) for the IdentityProvider adapter, and delegated Graph access (data) for the SourceAdapter in Sprint 2.

### 4.1 M365 Developer tenant

- Sign up at developer.microsoft.com/microsoft-365/dev-program. "Instant Sandbox" so it comes pre-seeded with sample users.
- Note tenant ID. Save in `docs/dev-setup.md`.

### 4.2 Entra app registration (single app, dual purpose)

- In the M365 dev tenant, register a single app.
- **For Sprint 1.5 (IdentityProvider):** enable ID-token issuance, add OIDC scopes (`openid`, `profile`, `email`), define app roles in the manifest (`helpdesk-tier-2`, `manager`, `admin` — match what the SIAM mapping expects), assign at least two test users to different roles.
- **For Sprint 2 (SourceAdapter):** add delegated permissions `Mail.Read`, `User.Read`. Reserve named slots for `Chat.Read`, `ChannelMessage.Read.All`, `Mail.Read.Shared` (later sprints).
- Redirect URIs:
  - For Edge OIDC sign-in (Sprint 2 Edge): `lehen://oauth/callback`
  - For browser admin sign-in (Sprint 1.5 admin UI): `http://localhost:8000/admin/oauth/callback` (dev) and the production admin URL (prod).
- Note client ID. Generate a client secret. Store via the Hub admin UI when configuring the IdentityProvider; never in `.env`, never in this file, never in git.

### 4.3 Keycloak dev instance

- `docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin quay.io/keycloak/keycloak:latest start-dev`
- Realm export checked into `ops/keycloak/lehen-realm.json` so a fresh contributor imports it in one click.
- Two test users mapped to the same realm roles as the Entra app roles, so SIAM mapping behaves identically across IdPs.

### 4.4 Documentation

- `docs/dev-setup.md` — covers both Keycloak and Entra paths from a fresh laptop.
- `docs/admin-bootstrap.md` — operator-facing procedure for the local bootstrap CLI and for emergency re-enable.

---

## 5. Phase breakdown

### Phase 0 — External setup and decisions

**Duration:** 0.5 day. Strict prerequisite for all code phases.

- M365 dev tenant + Entra app per §4.
- Keycloak realm export checked in.
- DESIGN.md §10 entries committed (§3.1–§3.4 above).

### Phase 1 — IdentityProvider abstraction and JWT generalization

**Duration:** 1 day. Independent of Phase 4.

1. Make JWT validation issuer-agnostic. Issuer URL, JWKS URL, audience claim all driven from configuration. The current Keycloak-shaped code presumed in `auth/jwt.py` and `auth/jwks.py` is generalized — Keycloak becomes one configuration, not the only configuration.
2. Define the `IdentityProvider` interface in code (`hub/src/lehen_hub/auth/identity_provider.py`). Methods per DESIGN.md §6: `authenticate()`, `get_claims()`, `revoke()`. Plus a `discovery_config()` method that returns the data `GET /auth/login-config` needs to expose to Edge.
3. Refactor existing Keycloak code as `KeycloakIdentityProvider` implementing the interface. No behavior change; tests should still pass.
4. Multi-issuer support in dev: the Hub config can list more than one IdP. In production a Hub deployment configures one. The validator accepts a token from any configured issuer; tests cover both.

### Phase 2 — EntraIdentityProvider implementation

**Duration:** 1 day. Sequenced after Phase 1.

1. `EntraIdentityProvider` implementing the interface.
2. OIDC discovery against `https://login.microsoftonline.com/{tenant_id}/v2.0/.well-known/openid-configuration`.
3. JWT signature validation against Microsoft's published JWKS.
4. Audience claim handling — Entra's `aud` is the client_id or `api://{client_id}`. The validator accepts both.
5. App-role claim mapping — JWT carries `roles: ["helpdesk-tier-2", ...]`. Lehen's existing realm-role-shaped consumer reads from this claim with no further translation.
6. Tenant-id validation — the `tid` claim must match the configured tenant id. Prevents a JWT from a different tenant being accepted by mistake.
7. Tests use a static keypair to issue Entra-shaped tokens; live tenant tests are documented but optional in CI.

### Phase 3 — `GET /auth/login-config` endpoint

**Duration:** 0.25 day. Trivial after Phase 1.

- Returns `{ provider: "keycloak" | "entra", discovery_url, client_id, scopes }`.
- Reads from the active SIAM IdP configuration.
- **Never** returns local-admin information.
- Unauthenticated (the user has no token yet).
- Tested: response shape matches what the Edge OIDC PKCE flow needs.

### Phase 4 — Local-admin bootstrap

**Duration:** 1.25 days. Independent of Phases 1–3 except for the auth dependency rule in Phase 5.

1. `LocalAdmin` collection in ArcadeDB with fields: `username`, `password_hash` (argon2id), `created_at`, `last_login_at`, `enabled`, `password_rotated_at`.
2. argon2id password hashing with conservative parameters (memory 64MB, iterations 3, parallelism 1 — adjust per OWASP 2024 recommendations).
3. `POST /admin/local-login` endpoint:
    - Body: `{ username, password }`.
    - Rate-limited per IP and per username (sliding window, 5 attempts per minute).
    - Lockout after 10 consecutive failed attempts (configurable).
    - Constant-time response regardless of whether the username exists.
    - On success: returns Hub-self-issued JWT with `iss: "lehen-hub-local"`, `scope: "admin"`, signed by the Hub key, expiry 1 hour.
    - Emits `LocalAdminLoginEvent` with username, IP, user-agent, success/failure, timestamp.
4. Auto-disable rule: when an admin logs in via SIAM (any `IdentityProvider`) with the admin role, set `enabled=false` on the `LocalAdmin` row. One-shot — re-enable is via CLI.
5. Bootstrap CLI command — `lehen-hub create-admin --username <name>`:
    - Generates a random password (24+ chars, full charset).
    - Argon2id-hashes it.
    - Inserts or replaces the single `LocalAdmin` row with `enabled=true`.
    - Prints the generated password to stdout once. Operator is responsible for capturing it.
    - On every re-run: any existing `LocalAdmin` row is overwritten, password is regenerated, previous password is permanently invalidated. Logs a `LocalAdminCredentialRotated` event to the audit trail.

### Phase 5 — Auth dependency hardening

**Duration:** 0.25 day. Sequenced after Phases 1, 2, 4.

1. User endpoints (`/me/*`, `/api/me/*`): the auth dependency rejects any JWT with `iss: "lehen-hub-local"`. Returns 401. Tested.
2. Admin endpoints (`/admin/*` excluding `/admin/local-login`): the auth dependency accepts SIAM-issued JWTs (with admin role claim) **or** Hub-self-issued JWTs (with `scope: "admin"`). Either passes.
3. The `/admin/local-login` endpoint is the only path where unauthenticated POST is expected. It is rate-limited and audited.

### Phase 6 — Tests

**Duration:** 1 day. Sequenced after Phases 1–5.

1. Both `IdentityProvider` adapters: happy path (valid token → CurrentUser), invalid signature, expired token, wrong audience, wrong issuer.
2. Cross-issuer rejection on user endpoints: local-issued JWT → 401 on `/me`. Tested explicitly.
3. Cross-surface rejection: SIAM-issued user-only JWT → 401 on `/admin/integrations` (no admin role claim). Local-issued JWT → 200 on `/admin/integrations` (scope=admin).
4. Local admin: rate-limit and lockout work as configured. Auto-disable on first SSO admin login flips `enabled=false`. CLI re-run regenerates password and invalidates the old one.
5. Audit trail: `LocalAdminLoginEvent` fires on every login attempt regardless of success.

### Phase 7 — Documentation

**Duration:** 0.25 day. Sequenced after Phase 6.

1. `docs/dev-setup.md` — set up Keycloak from realm export; set up Entra dev tenant + app from scratch.
2. `docs/admin-bootstrap.md` — `lehen-hub create-admin` usage; emergency re-enable procedure; cross-reference to backlog item #2 (further hardening).

---

## 6. Out of sprint

| Item | Where |
|---|---|
| 2FA on local admin | Backlog #1 |
| Further hardening of local admin (time-windowed validity, IP allowlist, multi-eye, out-of-band confirmation, audit alerting integration, HSM signing key) | Backlog #2 |
| Multiple local admins | Out — single bootstrap admin is the design |
| Web-based first-time setup wizard | Out — CLI-only for v1 |
| Okta / Auth0 / Ping / generic SAML adapters | Wanted contributions per DESIGN.md §8 |
| Per-deployment IdP-switch UI in admin | Out — config-file controlled in v1 |

---

## 7. Cut points if the sprint slips

In order of preference. Each cut is the minimum reversible step.

1. **Drop Entra app-role claim mapping.** Use group-id mapping with admin manually translating GUIDs in SIAM mapping. Saves ~0.25 day. Less polished but works.
2. **Drop bootstrap CLI auto-print of password.** Operator does manual SQL to seed the first admin (documented in `admin-bootstrap.md`). Saves ~0.25 day. Worse UX.
3. **Drop multi-issuer support in dev mode.** Hub configures exactly one IdP at a time. Saves ~0.25 day. Closes off mixed-mode dev (you'd switch by reconfig+restart instead of side-by-side test).
4. **Drop `EntraIdentityProvider` to next sprint.** Sprint 1.5 ships only Keycloak refactored behind the interface. Sprint 2 adds Entra. Saves 1 day. **Avoid this cut** — it puts Sprint 2 demo against Microsoft accounts at risk.

---

## 8. Definition of done

The sprint is done when, against a fresh Hub:

1. Configuring Hub with `provider: "keycloak"` and a Keycloak issuer makes Keycloak-issued JWTs pass on `/me/*`. Reconfiguring with `provider: "entra"` and an Entra tenant id makes Entra-issued JWTs pass on `/me/*`. Switching via config + restart, no code change.
2. `GET /auth/login-config` returns the active provider's discovery URL, client_id, and scopes. Edge (Sprint 2) can run OIDC PKCE against it without further config.
3. `lehen-hub create-admin --username admin` prints a one-time password. `POST /admin/local-login` with that username and password returns a Hub-self-issued JWT.
4. Re-running `lehen-hub create-admin --username admin` invalidates the previous password (test passes).
5. The local-issued JWT is accepted on `/admin/integrations` and rejected on `/me/connections`. Tests pass for both directions.
6. After a SIAM admin logs in once, the `LocalAdmin` row's `enabled` flag is `false`. Subsequent local-login attempts return 401 even with the correct password. Operator must re-run the CLI to re-enable.
7. `LocalAdminLoginEvent` rows exist for every local login attempt — successful and failed — distinct from regular `LoginEvent`.
8. `docs/dev-setup.md` is reproducible by a fresh contributor on a fresh laptop in under an hour.

The sprint is **not** done if any of: 2FA is implemented (backlog item), the local admin path is reachable from Edge (architecture violation), or local-issued JWTs are accepted on user-facing endpoints (security violation).
