# Lehen

> Open-source on-premise knowledge platform that binds knowledge to roles, not people — captured as a side effect of normal work across mail, Teams, and ITSM.

**Status:** Hub auth foundation and OAuth machinery are implemented and tested; Edge desktop client scaffold compiles and integrates with the Hub. The first end-to-end vertical slice against a real Microsoft Graph tenant is the active next step. See [DESIGN.md](DESIGN.md) for the architectural commitments and [docs/](docs/) for sprint-level design and operator docs.

---

## What it is

Lehen is an open-source, on-premise platform for organizational knowledge in enterprise IT environments. It binds knowledge to **roles**, not to **people**: when a role passes from one person to another, the projection of knowledge stays — captured as a side effect of normal work, triangulated across mail, Teams, and ITSM systems.

The name comes from the medieval German concept of a *fief* (Lehen) — something held for the duration of a role, never owned. When the holder steps out, the fief remains. This is the architectural thesis of the system in one word.

**Privacy-first by architecture.** Customer data never leaves customer infrastructure. The Hub runs on-premise; the Edge runs as a user-permission application on the workstation; only abstracted knowledge — never raw content — crosses the boundary.

## Why

Organizations lose institutional knowledge in the gap between systems. A question asked over Teams gets answered in a private message; the ticket closes with "issue resolved" while the actual answer lives only in a chat history. Traditional knowledge management tools require explicit documentation as a separate task — which never happens consistently in the real flow of work.

Lehen detects these capture moments by triangulating across mail, Teams, and ITSM tickets. When the same person, around the same time window, has a ticket in flight, a Teams conversation about it, and a mail thread referencing the ticket number, that is a capture moment. The abstracted knowledge — decision made, runbook executed, variation noted — is offered for confirmation and projected into the organizational graph.

## Architecture overview

```
+----------------------------+              +-----------------------+
|  EDGE (per workstation)    |   filtered   |  HUB (on-premise)     |
|                            |  knowledge   |                       |
|  Tauri v2 + React          |  -------->   |  FastAPI + ArcadeDB   |
|  - outlook-edge-com (COM)  |   (no raw    |  - outlook-graph      |
|  - Local KB cache          |    content)  |  - teams-graph        |
|  - Privacy filter          |              |  - itsm-rest-generic  |
|                            |              |  - Ollama (LLM/embed) |
|                            |              |  - Keycloak / Entra   |
+----------------------------+              +-----------------------+
```

Source adapters split between Edge-local (Outlook COM on the workstation) and Hub-side (Microsoft Graph for Outlook + Teams, REST for ITSM). The split is not arbitrary — it follows where each source's auth boundary naturally sits. Full architectural reasoning, plugin contracts, and decisions log are in [DESIGN.md](DESIGN.md).

## Technology

| Layer | Choice |
|-------|--------|
| Hub language | Python 3.12 + FastAPI |
| Hub deployment | Docker Compose / Helm chart |
| Edge language | Rust + Tauri v2 (edition 2024) |
| Edge frontend | React 18 + Vite |
| Edge platforms (v1) | Windows only |
| Graph database | ArcadeDB (Postgres wire protocol) |
| LLM / Embeddings | Ollama (default), swappable through plugin interfaces |
| Identity | Keycloak and Microsoft Entra ID — both first-class; other providers (Okta, Auth0, Ping, generic SAML) via the `IdentityProvider` plugin interface |

## What's shipped today

This is an evolving project. As of the current commit:

**Hub (`hub/`)**
- FastAPI server with admin CRUD for integration instances, SIAM role-to-instance mapping, encrypted-at-rest secret storage, and a tamper-evident admin audit trail.
- `IdentityProvider` plugin interface with Keycloak and Microsoft Entra both as first-class implementations, switched by a single config field.
- Local-admin bootstrap and break-glass auth path (argon2id, rate-limit, lockout, auto-disable on first SSO admin login). Strict surface separation: admin-issued JWTs only reach `/admin/*`.
- Full OAuth-2 PKCE machinery for source adapters: HMAC-encrypted state, code exchange, refresh-once-then-stale, encrypted token storage, admin-action revoke cascade (instance disable/delete/SIAM mapping change), multi-mailbox-ready connection schema (`external_subject` + `display_label`).
- `outlook-graph` source adapter (Microsoft Outlook via Graph API): authorization URL, code exchange, identity fetch from Graph `/me`, health probe.

**Edge (`edge/`)**
- Tauri v2 + React 18 desktop scaffold targeting Windows. Compiles cleanly (`npm run build` and `cargo check`).
- OIDC PKCE Hub-login flow against Keycloak or Entra (whichever the Hub is configured for) — system-browser launch, deep-link callback, token exchange, OS-credential-store token storage.
- Connect-flow wiring through the Hub's `/me/connections/{id}/initiate` and `/complete` endpoints.

**Not yet end-to-end interactively tested**
- A live login round-trip against a real Keycloak or Entra dev tenant.
- A real Microsoft consent → Graph round-trip for `outlook-graph`.
- The signed Windows MSI installer.

These are the explicit next step (Sprint 2 Phase 4 — see `docs/sprint2_design.md`).

## Quickstart (dev)

```bash
# Hub — see docs/dev-setup.md for the full walkthrough (Keycloak + Entra)
cd hub
uv sync
uv run uvicorn lehen_hub.main:app --reload

# Edge (Windows) — runs in dev mode, points at a local Hub
cd edge
npm install
npm run tauri:dev
```

A signed MSI installer for end users ships with the first release after Sprint 2 Phase 4 completes.

## Contributing

Lehen is built as an open-source project with the explicit goal of community-built adapters for identity providers, ITSM connectors, and platform builds the maintainer cannot test in isolation. See [CONTRIBUTING.md](CONTRIBUTING.md) for high-impact wanted contributions and the plugin interface contracts.

## License

Lehen is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for trademark notice.

The "Lehen" name is a trademark of Sven Andreas. Forks and derivative works must operate under a different name. See [NOTICE](NOTICE) for the full trademark policy.

## Maintainer

Sven Andreas — [github.com/dx111ge](https://github.com/dx111ge)
