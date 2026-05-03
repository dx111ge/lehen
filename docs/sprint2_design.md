# Sprint 2 — outlook-graph end-to-end + Edge bootstrap

**Status:** planned, not started
**Sprint window:** to be set
**Predecessor:** Sprint 1.5 (`docs/sprint1_5_design.md` — IdentityProvider abstraction + local-admin bootstrap). Sprint 2 assumes Sprint 1.5 has shipped.

---

## 1. Goal

Ship the first real `SourceAdapter` (Outlook via Microsoft Graph) end-to-end from a working Tauri-based Edge:

- Admin curates an `outlook-graph` `IntegrationInstance` in the Hub.
- User logs into the Edge on Windows, sees the curated instance in their connection list, clicks **Connect**, walks through the Microsoft consent prompt in the system browser, and lands back in the Edge with a `connected` connection that has a real `last_health_status` from a Graph `/me` round-trip.

This sprint is the **plumbing sprint**. It proves the OAuth machinery, the desktop-OAuth callback flow, the Edge↔Hub auth handshake, and the privacy gates around admin-curated integrations. No payload capture, no privacy filter, no MSI installer.

The data model lands **multi-mailbox-ready**, but the UX in this sprint stays single-mailbox (primary `/me` only). Shared-mailbox enumeration and per-connection picker UI are explicitly deferred to Sprint 3 — additive, no schema migration.

---

## 2. Predecessor state at sprint start

What Sprint 1 ships:

- Admin CRUD for `IntegrationInstance` with AES-256-GCM encryption of secret fields and HMAC fingerprint audit (`hub/src/lehen_hub/admin/integrations_service.py`).
- Hardcoded integration types registry (`hub/src/lehen_hub/integrations/registry.py`) with `outlook-com`, `teams-graph`, `itsm-rest-generic`.
- SIAM mapping service — admin maps realm roles to allowed integration instances.
- `MeService.me()` filters the user's visible instances by `siam_mapping ∩ enabled` (`hub/src/lehen_hub/user/me_service.py:50-79`).
- `connections_service.grant` creates a **stub** `IntegrationConnection` (`status="stub-connected"`, `encrypted_credentials=None`) and emits a `ConsentEvent`.
- LLM admin UX with provider dropdown (`6326b84`).
- `.env` stripped to bootstrap-required only (`b217e5a`).
- Empty `edge/` directory.

What Sprint 1.5 ships (prerequisite for this sprint):

- `IdentityProvider` interface formalized in code with two first-class implementations: `KeycloakIdentityProvider`, `EntraIdentityProvider`. Either can be the configured SIAM IdP for a Hub deployment.
- `GET /auth/login-config` endpoint returning the active SIAM provider's OIDC discovery URL, client_id, and scopes — the endpoint Sprint 2's Edge calls to learn which IdP to PKCE against.
- Local-admin bootstrap path with strict scope rules. Local-issued JWTs are valid only on `/admin/*`; auto-disable on first SSO admin login; never returned by `/auth/login-config`.
- M365 dev tenant + Entra app already provisioned. The Sprint 1.5 Entra app already carries `Mail.Read` and `User.Read` delegated permissions; this sprint reuses the same app for `outlook-graph` source-side OAuth.

What is **not** in place and this sprint relies on landing it:

- No real OAuth client for `SourceAdapter` data access. No token storage. No token refresh. No `health()` round-trip against any source.
- No Edge code at all.
- No `outlook-graph` `IntegrationType` in the registry.
- No `connection_cardinality` declaration on `IntegrationType` (admin can mis-configure single-vs-multi today).
- `connections_service.grant` enforces gate 1 (instance enabled) but **not** gate 2 (SIAM mapping). A direct API call with a known instance ID bypasses SIAM. Security gap to fix.
- Connection ID format `{user_sub}:{instance_id}:{seq}` collides on re-grant after revoke in single-connection mode. Bug to fix.
- No admin-action revoke cascade. Disabling or deleting an `IntegrationInstance`, or removing a SIAM mapping, leaves orphan `IntegrationConnection` rows unchanged.
- `IntegrationConnection` lacks `external_subject` and `display_label` — needed even for single-mailbox connections so the data model is multi-mailbox-ready and Sprint 3 can ship the picker without a schema migration.

---

## 3. DESIGN.md decisions to record before coding

These are architectural decisions surfaced during sprint planning. Record them in DESIGN.md §10 (decisions log) before any code lands so contributors hit the rationale, not the consequence.

### 3.1 Outlook-COM and Outlook-Graph are different adapters

**Decision (2026-05-03):** Rename existing `outlook-com` registry id to `outlook-edge-com`. Add `outlook-graph` as a separate Hub-side adapter.

**Reason:** they are not the same adapter. Different runtime (Edge COM vs. Hub HTTPS), different auth model (no creds vs. Entra OAuth), different deployment story (zero admin involvement vs. one-time tenant-admin consent), different data scope (local Outlook session vs. user's M365 mailbox plus optionally delegated shared mailboxes). Conflating them under one id leaves admin and user UX ambiguous about which is being configured.

### 3.2 "No admin approval needed" applies to Edge install only

**Decision (2026-05-03):** clarify §4 of DESIGN.md. The "no IT admin approval" promise covers Edge installation under user permissions. **It does not cover data sources that legitimately require tenant-admin consent** — Microsoft Graph adapters (mail, Teams) require the customer's Entra admin to consent to the Hub's app registration once per tenant.

**Reason:** delegated Graph auth requires consent for the requested scopes. The user-permission story is intact for Edge install and for adapters whose authn happens locally (`outlook-edge-com`), but the bottom-up adoption arc for Graph-based sources is gated on a one-time admin act. Hiding this distinction would create a contributor surprise and a customer trust problem when the consent prompt appears.

### 3.3 Connection cardinality is a property of the source type

**Decision (2026-05-03):** Add `connection_cardinality: Literal["single", "multi"]` to `IntegrationType`. Validate in `IntegrationsService.create/update` that `instance.multi_connection_allowed` is consistent with the type's declared cardinality. Single-cardinality types reject `multi_connection_allowed=true`.

| Type | Cardinality | Reason |
|---|---|---|
| `outlook-edge-com` | `multi` | Outlook can have multiple stores/profiles per user |
| `outlook-graph` | `multi` | Delegated `/me` mailbox plus zero-or-more shared mailboxes |
| `teams-graph` | `single` | One Teams identity per Entra tenant per user |
| `itsm-rest-generic` | `single` | One ITSM identity per system per user |

**Reason:** Without this, admin can mis-configure an instance (e.g., `multi=true` on a single-identity type), creating connection rows with no semantic meaning and breaking the one-active-per-user invariant assumed by the privacy and audit layers.

### 3.4 Edge framework: Tauri + React (recalibrated and confirmed)

**Decision (2026-05-03):** Confirm Tauri as the Edge runtime and pick **React** as the frontend framework, after explicit comparison against Avalonia (.NET 8) and WinUI 3, and against Svelte / Solid as React alternatives.

**Reason for Tauri over Avalonia / WinUI 3:**
- Graph view is the Edge UX centerpiece (2D primary, 3D fallback). The web rendering ecosystem (`react-force-graph`, Cosmograph, Three.js) is materially better than XAML's; Avalonia's escape hatch is to embed WebView2, which recreates Tauri with extra steps and a bigger binary.
- Install size: ~5–15MB Tauri vs. ~50–80MB .NET self-contained. Privacy-first/on-prem messaging is undermined by an 80MB user install.
- Cross-platform path is more mature in Tauri v2 (Windows + macOS + Linux + mobile). WinUI 3 is Windows-only and disqualified by DESIGN.md §8's macOS/Linux v2 commitment.
- License purity: Tauri is MIT/Apache 2.0 throughout.

**Reason for React over Svelte / Solid:**
- Edge has a real enterprise application surface — graph view, audit trail viewer, privacy controls, search — not just a connection screen. Enterprise component ecosystems are most mature in React (MUI, Ant Design, Mantine, Chakra).
- `react-force-graph` (2D + 3D, GPU-accelerated, well-maintained) gives the centerpiece graph viz for free with idiomatic React components.
- Contributor pool matters more than bundle size for an open-source project that explicitly expects community contributions.
- Bundle-size delta over Svelte (~50KB gzipped) is immaterial in a desktop context where Tauri's WebView2 is already present.

**Reassessment triggers — revisit if any of these surface in real use:**
- WebView2 deployment friction in customer-locked-down Windows images (especially Win10 LTSC or AppLocker/WDAC environments where WebView2 must be explicitly allowlisted).
- `react-force-graph` or Cosmograph performance falling short at expected node counts in a real Hub's projection.
- Contributor patterns showing one of the alternatives (Avalonia, Svelte) would have been materially better.

Trade-offs accepted up front:
- WebView2 runtime dependency on Windows. Mitigation: Tauri's installer bundles the WebView2 bootstrapper; covered in deployment documentation.
- Outlook COM access from Rust (via `windows-rs`) is more boilerplate than .NET COM interop. Mitigation: contained to the future `outlook-edge-com` adapter; not on Sprint 2's path.
- Smaller .NET-flavored DACH-enterprise contributor base. Mitigation: long-term concern, not Sprint-2 concern.

### 3.5 Custom URL scheme for OAuth callback

**Decision (2026-05-03):** `lehen://oauth/callback`. Registered by the Tauri app on Windows install (or on first launch in dev mode).

**Reason:** desktop apps cannot host an HTTPS redirect URI. The standard pattern is a custom URL scheme. `lehen://` is short, distinctive, and matches the project name. Reserve `lehen://oauth/...` namespace for all future provider callbacks.

### 3.6 Revoke-by-admin visibility to the user

**Decision (2026-05-03):** Visible by default. `/me` returns connections with a `revoked_by` annotation (`"admin-disable"`, `"admin-delete"`, `"siam-change"`) and a timestamp when applicable. Edge UI renders a brief explanation. Hub config flag `admin.revoke_visibility = "visible" | "silent"` permits per-deployment suppression for customer policies that require it; default is `visible`.

**Reason:** the privacy ethos in DESIGN.md §7 (personal audit trail, transparency over what happens to the user's data) is incompatible with silent admin-driven revokes. The escape hatch exists for legitimate edge-case customer policies (works councils, regulatory contexts that limit upward visibility of admin actions), but it must be a deliberate opt-out, not a default. Audit trail records every admin action regardless of the visibility flag.

### 3.7 OAuth `state` parameter strategy

**Decision (this sprint):** `state` is an HMAC of `(user_sub, integration_instance_id, nonce, issued_at)`, signed with a Hub-side secret. Verified on the callback. No server-side state lookup needed; the `state` is self-validating.

**Reason:** stateless validation is cheaper and more reliable than session-table lookups. Issued-at + nonce prevent replay; the HMAC prevents tampering. Standard pattern for OAuth callbacks against desktop callers.

### 3.8 Token refresh policy on `health()` failure

**Decision (this sprint):** on a 401 from a `health()` round-trip, the token is refreshed once and the call retried. On a second failure, the connection is marked `stale` and surfaced in `/me` with that status. The user can re-Connect from Edge, which re-runs OAuth.

**Reason:** the common case is an expired access token; refresh-and-retry handles it transparently. The rare case is a real auth break (revoked refresh token, deleted Entra app); marking `stale` rather than silently retrying avoids a refresh storm against Microsoft and surfaces the issue to the user without admin intervention.

---

## 4. External environment setup

The M365 Developer tenant and Entra app are already provisioned in Sprint 1.5 (per `sprint1_5_design.md` §4). Sprint 2 reuses them and only adds what's specific to the source-side OAuth.

### 4.1 Verify Sprint 1.5 setup is in place

- M365 Developer tenant active; tenant ID recorded in `docs/dev-setup.md`.
- Entra app registered with `Mail.Read` + `User.Read` delegated permissions (Sprint 1.5 added these).
- Entra app already configured with `lehen://oauth/callback` redirect URI (Sprint 1.5 set this for Edge OIDC sign-in; the same URI handles `outlook-graph` source OAuth).

### 4.2 Configure `outlook-graph` `IntegrationInstance` in Hub admin UI

- Once Phase 2 lands the registry entry, an admin (logged in via SIAM admin role from Sprint 1.5) creates an `outlook-graph` instance with the dev tenant's tenant_id, client_id, and client_secret.
- Map this instance to a SIAM role assigned to the test user.

### 4.3 ServiceNow Personal Developer Instance (parallel, not critical path)

- Sign up at signup.servicenow.com. Note instance URL and admin credentials.
- Confirm REST API is reachable and a sample table can be queried.
- **Out of sprint critical path.** If provisioning fails or hibernates this week, the sprint is unaffected — ServiceNow ships in Sprint 4.

---

## 5. Phase breakdown

Five phases, partially parallelizable. Calendar estimate assumes one full-time engineer; treat days as effort estimates not wall-clock.

### Phase 0 — Decisions and verification

**Duration:** 0.25 day. Strictly serial, blocks all other phases.

- DESIGN.md updates committed (§3.1–§3.8).
- Sprint 1.5 setup verified per §4.1.
- `outlook-graph` `IntegrationInstance` created in Hub admin UI per §4.2 (this lands once Phase 2 ships the registry entry — for Phase 0 the verification is just that the Sprint 1.5 Entra app + admin login is working).

### Phase 1 — Hub data-model and security gaps

**Duration:** 2 days. Can run in parallel with Phase 3.

The pre-existing security and consistency gaps in `connections_service` and `integrations_service` are fixed before any new adapter ships. No new feature is built on top of broken invariants.

1. **`connection_cardinality` on `IntegrationType`** (§3.3). Update `integrations/registry.py`, set values for the four current types, validate in `IntegrationsService.create/update`. Tests for valid and invalid combinations.
2. **SIAM gate enforcement in `connections_service.grant`**. Resolve the user's roles → SIAM-mapped instance set → reject with `403 IntegrationNotAuthorizedForRoleError` if requested instance not in the set. Test: direct API call to grant an existing+enabled instance not mapped to the user's roles returns 403, no `IntegrationConnection` row, no `ConsentEvent`.
3. **Connection-ID collision fix.** Replace the "single-connection means seq=0 forever" assumption with "single-connection means at most one active row per (user, instance)". Always-monotonic seq. Re-grant after revoke increments seq, no primary-key collision. Test: grant → revoke → grant succeeds, both rows in DB, only the second is active.
4. **Multi-mailbox data model (Layer 1 only).** Add `external_subject: str` and `display_label: str` to `IntegrationConnection`. Uniqueness constraint becomes `(user_sub, integration_instance_id, external_subject)` where `disconnected_at IS NULL`. For the single mailbox case in this sprint, `external_subject` is populated from Graph `/me` SMTP address; `display_label` is the user's mailbox display name. Test: schema migration roundtrip; existing single-row connection from sprint 1 migrates with `external_subject` empty string and stays valid until next grant.

### Phase 2 — Hub OAuth machinery and outlook-graph adapter

**Duration:** 2.5 days. Sequenced after Phase 1.

1. **Generic OAuth-2 helper.** Authorization-code with PKCE. Provider-agnostic. Inputs: auth URL, token URL, scopes, client_id, client_secret, redirect_uri. Outputs: `(access_token, refresh_token, expires_at, scope_granted, external_subject, display_label)`. The `external_subject` and `display_label` are extracted by a provider-specific callback the helper invokes after token exchange (for Graph: `GET /me`).
2. **Token storage.** Reuse `IntegrationConnection.encrypted_credentials` (already exists, already encrypted via `crypto.encrypt`). Payload: `{access_token, refresh_token, expires_at, scope}`. Lazy refresh on expiry.
3. **`outlook-graph` `IntegrationType`.** Fields: `tenant_id` (uuid), `client_id` (uuid), `client_secret` (secret). Cardinality: `multi`. Display name: "Microsoft Outlook (Graph API)".
4. **Wire `connections_service.grant` to use OAuth.** Replace stub creation with: initiate OAuth → return auth URL to caller → caller redirects user → user consents in browser → callback delivers code to Hub → Hub exchanges for tokens → Hub calls `health()` (Graph `/me`) → Hub writes `IntegrationConnection` with real `encrypted_credentials`, `external_subject`, `display_label`, `last_health_status="ok"`, `status="connected"`. Emit `ConsentEvent`. Returns the connection record.
5. **Admin-action revoke cascade.** Three triggers (each its own commit):
    - `IntegrationsService.update(enabled=False)` → revoke all active connections for this instance. Status `disconnected`. ConsentEvent `action="revoked-by-admin-disable"`. Token wiped (`encrypted_credentials=null`).
    - `IntegrationsService.delete(instance_id)` → same as above plus instance row removed.
    - `SIAMService.update(mapping)` → recompute per-user authorized-instance set. For any user whose role intersection with the new mapping no longer includes a currently-connected instance, revoke that connection. ConsentEvent `action="revoked-by-siam-change"`.

### Phase 3 — Edge bootstrap

**Duration:** 3 days. Can start in parallel with Phase 1 once Phase 0 is done. Tauri + React per §3.4.

1. **Tauri v2 + React scaffold.** `cargo tauri init` in `edge/` with the React template. Project compiles and `cargo tauri dev` launches an empty window. WebView2 bootstrapper bundled into the dev build.
2. **Custom URL scheme registration.** `lehen://` scheme registered via Tauri configuration. Tested: opening `lehen://oauth/callback?code=foo` in a browser brings the Edge app to the foreground with the URL passed to a handler.
3. **IdP discovery via Hub.** Edge calls `GET /auth/login-config` on the Hub (the endpoint Sprint 1.5 ships) to learn which SIAM IdP to PKCE against and what client_id/scopes to use. Edge carries no IdP knowledge of its own — Keycloak vs. Entra is decided per Hub deployment, not per Edge build.
4. **OIDC PKCE sign-in.** Against whichever IdP the login-config endpoint returned. System browser handoff. Token returned via `lehen://` callback. Stored in OS-native secret store (Windows Credential Manager via Tauri's secure storage). Edge displays "logged in as <username>" once successful.
5. **`/api/me` integration.** Edge calls `GET /me` with bearer token. Renders the list of authorized integration instances. Each row shows `display_name`, `type`, current connection `status` (one of `needs_connect` / `connected` / `stale` / `revoked-by-admin`), `display_label` (mailbox identity once connected), and a **Connect** button (visible if status is `needs_connect`). Per §3.6, when the status reflects an admin-driven revoke, a brief explanation is rendered (config-suppressible per-deployment).
6. **Connect flow.** Click Connect → Edge calls `POST /me/connections/<instance_id>/initiate` → Hub returns the OAuth auth URL with the HMAC-encoded `state` per §3.7 → Edge opens system browser to that URL → user consents in Microsoft → browser redirects to `lehen://oauth/callback?code=...&state=...` → Edge picks up the URL → forwards code+state to Hub via `POST /me/connections/<instance_id>/complete` → Hub validates state, exchanges code for tokens, calls Graph `/me` to populate `external_subject` and `display_label`, calls `health()`, stores the connection → Edge refreshes the list to show `connected`.

### Phase 4 — Vertical slice test

**Duration:** 1 day. Strictly serial after Phase 2 and Phase 3.

Manual end-to-end runs twice — once with Keycloak as the configured SIAM IdP, once with Entra — to prove the IdP abstraction holds end-to-end.

1. Hub running locally via `docker compose up`.
2. `cargo tauri dev` to launch Edge.
3. In Hub admin UI: create `outlook-graph` `IntegrationInstance` with the tenant_id/client_id/client_secret from the M365 dev tenant. Map it to a SIAM role the test user has.
4. In Edge: log in as the test user. Edge calls `/auth/login-config`, receives the active IdP's discovery URL, runs OIDC PKCE against it, lands back logged in.
5. Edge displays the `outlook-graph` instance with status `needs_connect`.
6. Click **Connect** → system browser opens → consent in Microsoft → browser redirects → Edge displays connection as `connected` with `display_label` showing the test user's mailbox.
7. Verify in Hub admin: `IntegrationConnection` row exists with `status="connected"`, `last_health_status="ok"`, `external_subject` populated with the test user's SMTP, `display_label` populated, `encrypted_credentials` not null. `ConsentEvent` row recorded with `action="granted"`.
8. In Hub admin: disable the instance. Verify the connection row flips to `disconnected`, `encrypted_credentials` is null, a second `ConsentEvent` records `action="revoked-by-admin-disable"`. In Edge, verify the connection now displays the admin-revoke explanation per §3.6.
9. Re-enable, re-grant from Edge. Verify a new connection row is created with `connection_seq=1`, `connection_seq=0` row remains as historical record.
10. Reconfigure Hub to use the other IdP (Entra ↔ Keycloak), restart, repeat steps 4–9. Verify the same flow works regardless of IdP — proves the IdentityProvider abstraction holds in the Edge round-trip.

Test plan does **not** include payload capture, privacy filter, or any actual reading of mail content. The slice ends at "Hub has live OAuth tokens against Graph and proved the round-trip with `/me`, end-to-end across both supported IdPs."

---

## 6. Out of sprint — explicit, with rationale

| Item | Why deferred |
|---|---|
| `Mail.Read.Shared` scope and shared-mailbox enumeration | Layer 2 of multi-mailbox. Sprint 3, additive, no schema migration. |
| Edge UI mailbox-picker (multiple connections per grant) | Sprint 3, depends on `Mail.Read.Shared` + enumeration. |
| Per-connection privacy class surfaced in Edge UI | Sprint 3, makes sense alongside the mailbox-picker. |
| Slack adapter | Reuses the OAuth helper; ~1 day in a follow-up sprint. |
| Teams adapter | Same Entra app, additional scopes; ~1 day in a follow-up sprint. |
| ServiceNow adapter | PDI provisioning runs in parallel; first ITSM adapter ships when the helper is proven. |
| `outlook-edge-com` adapter | Win32 COM in Rust; own sprint with its own risk profile. |
| Actual mail capture and abstraction | This is the *connection plumbing* sprint, not the *capture* sprint. |
| Privacy filter implementation | No payload yet to filter. |
| MSI installer + signing + auto-updater | Demo runs from `cargo tauri dev`. Productisation is a separate stream. |

---

## 7. Cut points if the sprint slips

In order of preference. Each cut is the minimum reversible step to recover the sprint without abandoning the goal.

1. **Drop ServiceNow PDI provisioning.** Pure parallel work, no dependency on it. If Phase 0 stretches, drop this from Phase 0.
2. **Drop Edge "Connect" button → admin pre-creates the connection.** Loses the desktop OAuth flow demo for this sprint, but proves the OAuth machinery via admin UI. Edge in this case becomes "log in, see your connections, see connected status". Phase 3 shrinks by ~1 day.
3. **Drop the custom URL scheme → callback returns to a Hub web page that displays a one-time code; user pastes the code into Edge.** Works, ugly. Recovery option for unexpected Tauri/Windows custom-scheme issues. ~0.5 day saved.
4. **Drop Edge entirely → outlook-graph adapter ships via admin UI only.** Last resort. This is the fallback if Tauri eats the week. Sprint becomes Hub-only, Edge bootstrap moves to Sprint 3. The Hub work (Phases 0–2 plus Phase 4 admin-side test) is still a coherent sprint by itself.

Cuts 2–4 each abandon a chunk of demo polish but never compromise the data model, security gates, or revoke cascade. Those land regardless.

---

## 8. Open questions

All sprint-scoping questions are resolved. Decisions captured in §3.4–§3.8.

---

## 9. Definition of done

The sprint is done when, against a fresh checkout, a fresh M365 dev tenant, and Sprint 1.5's Keycloak + Entra both available:

1. The vertical slice in §5 Phase 4 runs successfully end-to-end with Keycloak as SIAM, then again with Entra as SIAM. Same flow, no code change between the two.
2. All security-gap tests in §5 Phase 1 pass (SIAM gate, connection-ID collision, admin cascade for all three triggers).
3. DESIGN.md decisions log records the eight entries in §3.
4. `docs/dev-setup.md` (extended from Sprint 1.5) covers the `outlook-graph` setup steps and is reproducible by a contributor without verbal handover.
5. The `outlook-graph` `IntegrationType` exists in the registry with `connection_cardinality="multi"` and the data model carries `external_subject` + `display_label` even though only one mailbox is captured per grant in this sprint.
6. Edge has zero hard-coded IdP knowledge — switching the Hub between Keycloak and Entra requires only Hub config + restart, no Edge rebuild.

The sprint is **not** done if any of: a Slack/Teams adapter exists, mail content has been read, the privacy filter is implemented, or there is an MSI installer.
