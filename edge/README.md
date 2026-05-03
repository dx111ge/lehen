# Lehen Edge

Windows-first Tauri v2 client for the Lehen Hub. Built with Rust + React.

This app is the user-side surface of Lehen — the user signs in to the Hub via the configured SIAM IdP (Keycloak or Entra), sees the integration instances their role is authorized for, and connects them via OAuth-2 against each source's IdP.

## Status

Sprint 2 Phase 3 scaffold. The shell builds, the OIDC PKCE flow + deep-link routing + Hub API integration are written. **Not yet runtime-tested end-to-end** — that requires a live Hub at `http://localhost:8000` with Keycloak or an Entra dev tenant configured. Phase 4 of the sprint covers the manual vertical slice.

## Prerequisites

- Rust 1.85 or newer (Tauri v2 + edition 2024).
- Node.js 20 or newer.
- On Windows: WebView2 runtime (preinstalled on Windows 11; Tauri's installer bundles the bootstrapper for older Windows 10 images).
- Tauri prerequisites: see [tauri.app prereqs](https://tauri.app/start/prerequisites/).

## Getting started (dev)

```bash
cd edge
npm install
npm run tauri:dev
```

The first invocation pulls the Tauri Rust dependencies and may take a few minutes. Subsequent runs are fast.

`tauri:dev` starts the Vite dev server on port 1420 and launches the Tauri window pointed at it. Hot-reload works for the React side; Rust changes require a rebuild.

## Build (release MSI)

```bash
cd edge
npm install
npm run tauri:build
```

Outputs an MSI under `src-tauri/target/release/bundle/msi/`.

The release build is unsigned in this scaffold. Production deployments need a code-signing certificate; see Sprint 2 design doc `docs/sprint2_design.md` §6 for the deferred packaging story.

## Configuration

The Edge reads its Hub URL from the environment at startup:

| Variable | Default | Purpose |
|---|---|---|
| `LEHEN_HUB_URL` | `http://localhost:8000` | Where the Hub is reachable. |

Everything else (which SIAM provider to use, the public client_id, the IdP discovery URL) the Edge fetches from the Hub's `/auth/public-config` endpoint at startup. Changing IdPs in the Hub's config does not require an Edge rebuild.

## Architecture

### Auth surfaces

Two distinct callback paths under the `lehen://` scheme:

* `lehen://auth/callback` — Hub-login OIDC PKCE response. The Edge does the token exchange itself against the IdP's token endpoint and stores the resulting access token in the OS Credential Manager.
* `lehen://oauth/callback` — source-adapter OAuth response (Sprint 2 outlook-graph and beyond). The Edge forwards the `code` + `state` to the Hub's `/me/connections/{id}/complete` endpoint; the Hub does the exchange and persists the connection.

### Token storage

Hub-bound bearer tokens are stored in:

| OS | Backend |
|---|---|
| Windows | Credential Manager |
| macOS | Keychain |
| Linux | Secret Service |

Tokens are read by the Rust side on demand and handed to the frontend through Tauri's IPC. They never touch the webview's `localStorage`, `sessionStorage`, or `IndexedDB`.

### Frontend

React 18 + TypeScript + Vite. Strict CSP set in `index.html` and `tauri.conf.json` — script-src is `'self'` only, network-src is the Hub plus HTTPS for IdP discovery.

### Backend

Rust + Tauri v2. Plugins:

* `tauri-plugin-deep-link` — registers the `lehen://` scheme and forwards inbound URLs to the frontend.
* `tauri-plugin-shell` — opens the system browser for OIDC and source-OAuth flows.
* `tauri-plugin-http` — desktop-friendly HTTPS client (HMR-aware in dev).

## What works

- Project compiles (`npm run build`, `cargo check`).
- Hub URL configuration via env var.
- Deep-link routing: `lehen://auth/...` vs. `lehen://oauth/...`.
- OIDC PKCE generation + auth-URL composition.
- Hub API client (`/auth/public-config`, `/me`, `/me/connections/{id}/initiate`, `/me/connections/{id}/complete`).
- Token storage via OS credential store.

## What is not yet end-to-end tested

- Real OIDC PKCE round-trip against a live Keycloak or Entra dev tenant.
- Real source-OAuth round-trip against Microsoft Graph (`outlook-graph`).
- Custom URL scheme registration on a fresh Windows install (works in `tauri dev`; behavior on a signed MSI install needs verification).
- Tauri release MSI and code signing.

These are explicitly Phase 4 of the sprint — see `docs/sprint2_design.md` §5 Phase 4.

## Contributing

The Edge is part of the Lehen monorepo. See repo-level `CONTRIBUTING.md` for the project-wide policy. Edge-specific points:

- Frontend additions go under `src/`. Strict TypeScript; `npm run typecheck` must pass before PR.
- Rust additions go under `src-tauri/src/`. New IPC commands need a corresponding entry in `capabilities/default.json`.
- Cross-platform compatibility matters even though Windows is v1's only supported platform — keep keyring usage, deep-link patterns, and HTTP code portable.
