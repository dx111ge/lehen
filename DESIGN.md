# DESIGN — Lehen

**Status:** Phase 1 architecture, fixed 2026-05-02
**Maintainer:** dx111ge (Sven)
**Repository:** github.com/dx111ge/lehen
**Domain:** lehen.io
**License:** Apache 2.0 + "Lehen" trademark notice

---

## 1. Project identity

Name: **Lehen** — from the medieval German legal concept of a *fief*: something held by a person for the duration of their role, but not owned. When the role passes, the fief remains, the holder steps out. This is the core architectural thesis of the system, captured in one word.

License: **Apache 2.0**, with a trademark notice for "Lehen" in the README and `NOTICE` file. Code is freely usable and forkable; the name is reserved to prevent hostile rebranding by third parties operating "Lehen Cloud" services or similar.

**Trademark notice (verbatim, to be placed in the NOTICE file):**

> "Lehen" is a trademark of Sven Andreas. The Apache 2.0 license grants rights to use, reproduce, modify, and distribute the source code, but does not grant rights to use the "Lehen" name, logo, or trademark to identify forked, modified, or hosted versions of this software. Forks and derivative works must operate under a different name. Commercial use of the "Lehen" name in any product, service, or marketing material requires written permission from the maintainer.

Repository strategy — clean cut from previous prototype, with continuity marker:

- New repo: `dx111ge/lehen` (this repo)
- Old repo: `dx111ge/central-knowledge` remains, README updated to: *"Pre-Lehen prototype — superseded by [lehen]. Kept as architectural reference for the April 2026 organisational-graph pivot."*

---

## 2. Architectural thesis

The unit of knowledge is the **role**, not the person.

Knowledge is a **projection** from a central organizational graph onto the role currently held. When a role passes from person A to person B, the projection is unchanged — the graph persists, the holder rotates. This is the *handover test*: same role, different person, identical access, no wipe.

Three layers of projection:

| Layer | Scope | Examples |
|-------|-------|----------|
| Organizational | Company-wide invariants | Compliance procedures, SLA definitions, standard runbooks |
| Departmental | Group-specific knowledge | Team conventions, internal escalation paths |
| Role | Current responsibilities | Active tickets, in-flight decisions, shadow communications |

The knowledge in each layer is captured as a side effect of normal work, not as an additional task. This is the central design principle that distinguishes Lehen from traditional KM systems, which require explicit documentation as a separate activity.

---

## 3. Primary use case: Shadow Support triangulation

The phenomenon Lehen targets does not appear in any single tool. It emerges from the *gap between* tools.

Example: Employee A is stuck on a ticket. They ask employee B over Teams chat. B answers with a paragraph that resolves the issue. The ticket gets closed with "issue resolved", but the knowledge — B's answer — exists only in their direct message. It is invisible to the organization.

Lehen detects these patterns by **triangulating across three sources**:

1. **Mail** (Outlook COM on the edge)
2. **Teams** (Microsoft Graph API)
3. **ITSM tickets** (REST against the configured ITSM)

When the same person, around the same time window, has a ticket in state X, a Teams conversation about its subject, and a mail thread referencing the ticket number — that is a capture moment. The abstracted knowledge (decision made, runbook executed, variation noted) is offered for confirmation and, if accepted, projected into the appropriate layer of the graph.

This is the *capture-as-side-effect* principle made operational.

---

## 4. Topology

```
+----------------------------+              +-----------------------+
|  EDGE (per workstation)    |   filtered   |  HUB (on-premise)     |
|                            |  knowledge   |                       |
|  Tauri app, Windows MSI    |  -------->   |  Docker / K8s         |
|  - Outlook COM connector   |   (no raw    |  - FastAPI server     |
|  - Teams Graph connector   |    content)  |  - ArcadeDB           |
|  - ITSM REST connector     |              |  - Ollama             |
|  - Local KB cache          |              |  - Keycloak           |
|  - Privacy filter          |              |                       |
+----------------------------+              +-----------------------+
```

**Hub** runs entirely on-premise. Customer data never leaves the customer infrastructure. This is non-negotiable — the audience (enterprise ITSM) handles regulated data (DSGVO, BSI, internal compliance) and would not adopt any architecture that relies on cloud-hosted services for data-in-flight.

**Edge** runs as a Windows user-agent (not a system service), installed by the user without administrator rights. This is structurally important for shadow-support adoption: if IT admin approval is required, bottom-up adoption dies before it starts.

**Privacy boundary** sits in the Edge, before any outbound call to the Hub. The filter strips raw content; only abstracted knowledge (decisions, runbook variations, patterns) is transmitted. The audit trail records what was captured for whom, but never the original text.

---

## 5. Technology stack

| Layer | Choice | Reason |
|-------|--------|--------|
| Hub language | Python 3.12 + FastAPI | ITSM practitioner audience is Python-fluent; OpenAPI-first matches API-first architecture; LLM client ecosystem is Python-native |
| Hub deployment | Docker Compose (small) / Helm chart (large) | Customer-deployed; never Lehen-hosted |
| Edge language | Rust | Single binary, native performance, fits user permissions, integrates with Windows COM |
| Edge framework | Tauri v2 | Native app window, MSI installer support, auto-updater, smaller footprint than Electron. Recalibrated 2026-05-03 against Avalonia/WinUI 3/Electron/Flutter; React picked as the frontend over Svelte/Solid for the graph-viz ecosystem and enterprise component density (see decisions log). |
| Edge frontend | React (inside Tauri WebView2) | Mature enterprise component ecosystem (MUI, Ant Design, Mantine); `react-force-graph` for the 2D/3D graph-view centerpiece; largest contributor pool. Bundle delta over Svelte (~50KB gzipped) immaterial in desktop context. |
| Edge platforms (v1) | Windows only | Outlook COM is Windows-only; Mac Outlook lacks COM; DACH ITSM audience >95% Windows |
| Graph database | ArcadeDB | Apache 2.0; multi-model (graph + document + vector + key/value); Cypher + SQL + Postgres wire protocol; OrientDB lineage (15 years); active monthly releases |
| Hub ↔ Graph protocol | PostgreSQL wire (`psycopg` or `asyncpg`) | Standard tooling, no Java client in Python codebase, DBA backup tools work natively |
| Embedding model runtime | Ollama (default) | Local execution, no data leakage, swappable through `EmbeddingProvider` interface |
| Inference model runtime | Ollama (default) | Same; swappable through `InferenceProvider` interface |
| Identity provider | Keycloak (default reference) | Open-source, on-premise, OIDC-conformant; swappable through `IdentityProvider` interface |
| Connector pattern | `SourceAdapter` plugin | Mail / Teams / ITSM each implement the same contract |

### Rationale notes for the harder choices

**Why ArcadeDB over Neo4j Community.** Neo4j Community is GPLv3, which is incompatible with Apache 2.0 server-side and is reflexively blocked by enterprise compliance teams. ArcadeDB is genuine Apache 2.0 with no enterprise-edition feature gating.

**Why ArcadeDB over FalkorDB.** FalkorDB uses a source-available license (not OSI-approved open source) and requires Redis as a runtime dependency. The license collision and the operational complexity of a Redis-dependent stack outweighed FalkorDB's performance lead.

**Why ArcadeDB over KuzuDB.** KuzuDB is archived as of early 2026. Building on an archived dependency is not viable for an OSS project seeking contributor adoption.

**Why two separate provider interfaces (Embedding vs Inference).** Embeddings are short, deterministic, hot-path, low-latency. Inference is long-form, generative, streaming, latency-tolerant. A unified interface forces tradeoffs in both. Separation lets operators run embeddings on a small CPU-only Ollama and inference on a separate vLLM GPU machine if they prefer.

---

## 6. Plugin interfaces

All replaceable components implement a documented interface. Default implementations ship in core; community contributions extend.

| Interface | Default | Documented contract |
|-----------|---------|---------------------|
| `SourceAdapter` | Outlook (COM), Teams (Graph), generic ITSM (REST) | `discover()`, `subscribe(filter)`, `fetch(id)`, `health()` |
| `EmbeddingProvider` | Ollama with `nomic-embed-text` | `embed(text) -> vector`, `dimensions()`, `health()` |
| `InferenceProvider` | Ollama with configurable model | `generate(prompt, params) -> stream`, `health()` |
| `IdentityProvider` | Keycloak via OIDC | `authenticate()`, `get_claims()`, `revoke()` |
| `PrivacyFilter` | Default rule-based + LLM check | `filter(payload) -> filtered_payload`, `audit_trail(filtered) -> record` |

The interfaces are kept minimal by design. Each interface contract fits in one short page of documentation. New adapters should require no Lehen core changes — if they do, the interface is wrong and gets revised.

---

## 7. Privacy architecture

Privacy is a Day-1 architectural property, not a Day-90 retrofit.

**Opt-in per employee.** No data flows from any Edge until the user has explicitly enabled Lehen for that source. Defaults are off. Consent is recorded in the audit trail with timestamp.

**Personal audit trail.** Every captured item is tagged with the originating user, source, timestamp, and the filter that produced it. Users can request their own audit trail at any time and request deletion of any captured item, which propagates to the graph.

**Source separation from knowledge.** Raw source content (mail body, Teams message text, ticket description) never enters the graph. The graph stores abstracted entities and relationships only. The original text remains in the source system, where it was already governed by the customer's existing data retention policy.

**Filter audit-ability.** The privacy filter sits at one well-defined location (Edge, before outbound). It is the first thing a customer's DPO will inspect. The implementation is therefore single-file, well-tested, and explicitly documented.

---

## 8. Out of scope for v1

These are explicit *non-goals* for the initial release. They are listed here so contributors with the right access can pick them up as community contributions, and so users do not expect them on day one.

| Area | Status | Why deferred |
|------|--------|--------------|
| Microsoft Entra ID adapter | Wanted contribution | Maintainer has no Entra tenant for testing |
| Okta adapter | Wanted contribution | Maintainer has no Okta tenant |
| Auth0 / Ping / other SAML providers | Wanted contribution | Same |
| macOS Edge build | Deferred to v2 | Outlook for Mac lacks COM; needs different Mail connector |
| Linux Edge build | Deferred to v2 | Limited business deployment; Teams desktop on Linux discontinued 2023 |
| ServiceNow connector | Wanted contribution | Maintainer's primary background is HP Service Manager |
| Jira / Atlassian connector | Wanted contribution | Common enough to be high-value |
| Studio-quality admin UI | Phase 2 | v1 has minimal browser-based admin; rich UI follows |

These are listed in `CONTRIBUTING.md` as *"high-impact wanted contributions"* with the documented interface specifications they target.

---

## 9. Open questions for next iterations

These are decisions deliberately not made yet. They will be resolved as the implementation forces them.

- **Capture pattern taxonomy.** Decision-request, runbook-execution with variation note, shadow-detection, escalation-pattern. The exact set and the detection heuristics need empirical refinement against real workflow traces.
- **Multi-tenant isolation in the Hub.** v1 assumes single-tenant per Hub deployment. Multi-tenant within one Hub is a v2 question.
- **Sync / replication strategy between Edges and Hub.** Push vs. pull, batching, conflict resolution. Will be driven by first real-world performance measurement, not premature design.
- **Graph schema migration strategy.** ArcadeDB has schema evolution; how Lehen exposes schema changes through migrations is TBD.

---

## 10. Decisions log

| Date | Decision | Alternatives considered | Reason |
|------|----------|-------------------------|--------|
| 2026-04-27 | Pivot from role-as-knowledge-unit to organization-as-knowledge-graph with role-based projection | Role-as-knowledge-unit (initial *central-knowledge* design) | Handover test fails for role-as-unit; projection model passes |
| 2026-05-02 | Project name: Lehen | Lehnos, Lehnara, Lehenta, Lehency, several others | Cleanest namespace; semantically precise to the architectural thesis; no SEO collisions |
| 2026-05-02 | License: Apache 2.0 + trademark notice | MIT, AGPL, BSL | Apache 2.0 passes enterprise compliance; trademark notice protects against hostile rebranding without forcing copyleft |
| 2026-05-02 | Repo strategy: new repo, old repo marked as Pre-Lehen reference | Archive old repo; parallel repos with no relation | Continuity-with-marker preserves the architectural pivot history and the Beran endorsement context |
| 2026-05-02 | Hub language: Python + FastAPI | Go, Rust | Audience fit (ITSM practitioners script in Python); LLM ecosystem maturity; sprint-energy preservation |
| 2026-05-02 | Edge language: Rust + Tauri | Python daemon + browser, Electron | Single binary; user-permission fit; MSI deployment; performance |
| 2026-05-02 | Edge platforms: Windows only for v1 | Cross-platform from day one | Outlook COM is Windows-only; DACH audience overwhelmingly Windows; defers cross-platform build complexity without architectural lock-in |
| 2026-05-02 | Graph database: ArcadeDB | Neo4j Community (GPLv3 collision), KuzuDB (archived), FalkorDB (source-available + Redis), Apache AGE (performance concerns), Memgraph/ArangoDB (BSL) | Only Apache 2.0 multi-model graph DB with active development, OrientDB heritage, native vector support, and Postgres-wire compatibility |
| 2026-05-02 | LLM/Embedding: Ollama default behind plugin interface | Sentence-Transformers in-process; cloud-only providers | Local execution; no data leakage; swappable for vLLM and others |
| 2026-05-02 | Two separate provider interfaces (Embedding vs Inference) | Single unified `LLMProvider` | Different hot-path profiles; allows mixed CPU-embedding + GPU-inference deployments |
| 2026-05-02 | Identity: Keycloak default behind `IdentityProvider` interface; concrete Entra/Okta adapters as community contributions | Direct Entra/Okta integration in core | Maintainer has no Entra/Okta tenant; community-contributed adapters expected |
| 2026-05-03 | Promote Entra `IdentityProvider` from community-contributed to first-class alongside Keycloak (Sprint 1.5) | Wait for community adapter; Microsoft-only stack | Entra is the most common enterprise IdP; building it alongside Keycloak now exercises the abstraction at the moment it's formalized; Keycloak remains the OSS-shop default. Other providers (Okta, Auth0, Ping, generic SAML) stay community-contributed. |
| 2026-05-03 | Local-admin auth as bootstrap and break-glass path; strictly admin-surface only (Sprint 1.5) | Pre-seed DB before first start; hardcoded SSO | Solves the chicken-and-egg of fresh-Hub IdP config. Single bootstrap admin per install, password regenerated on every CLI re-run, auto-disable on first SSO admin login. Hub-self-issued JWTs (`iss=lehen-hub-local`) accepted only on `/admin/*`; rejected on `/me/*`. Backed by argon2id, rate-limit, lockout, dedicated `LocalAdminLoginEvent` audit. |
| 2026-05-03 | Edge speaks only to Hub for IdP discovery (Sprint 1.5) | Edge holds IdP config; per-customer Edge builds | `GET /auth/public-config` on the Hub returns the active SIAM provider's OIDC discovery URL, client_id, and scopes. Edge runs OIDC PKCE against whichever IdP the Hub names. Local-admin path is never returned by this endpoint. |
| 2026-05-03 | Strict separation of admin and user auth surfaces (Sprint 1.5) | Single auth dependency for both surfaces | User surface (`/me/*`) accepts SIAM-issued JWTs only. Admin surface (`/admin/*`) accepts SIAM-issued (with admin role claim) or Hub-self-issued (`scope=admin`). Surfaces share zero auth code beyond signature verification. Cross-issuer rejection is tested explicitly. |
| 2026-05-03 | Outlook-COM and Outlook-Graph are different `SourceAdapter`s (Sprint 2) | Single `outlook` adapter conflating both | Different runtime (Edge COM vs. Hub HTTPS), different auth model (no creds vs. Entra delegated), different deployment story. Renaming `outlook-com` → `outlook-edge-com`; adding `outlook-graph` as separate Hub-side adapter. |
| 2026-05-03 | "No admin approval needed" promise applies to Edge install only (Sprint 2 clarification of §4) | Promise covers all data sources | Microsoft Graph adapters (mail, Teams) require tenant-admin consent for the Hub's app registration once. The user-permission story is intact for Edge install and for `outlook-edge-com` (local Outlook session); bottom-up adoption for Graph-based sources is gated on a one-time admin act. |
| 2026-05-03 | Connection cardinality is a property of the source type (Sprint 2) | Per-instance flag with no type-level constraint | Add `connection_cardinality: Literal["single", "multi"]` to `IntegrationType`. Enforced in admin services. Single-cardinality types reject `multi_connection_allowed=true`. Aligns the data model with the semantic of each source. |
| 2026-05-03 | Edge framework: Tauri + React, recalibrated and confirmed (Sprint 2) | Avalonia/.NET 8, WinUI 3, Electron, Flutter; Svelte/Solid as React alternatives | Web rendering ecosystem (`react-force-graph`, Cosmograph, Three.js) is materially better than XAML's for the graph-view centerpiece; Tauri install size (~5–15MB) preserves the privacy-first/lightweight pitch; cross-platform path (Tauri v2) intact for v2. React over Svelte/Solid for enterprise component ecosystem and contributor pool. Reassessment triggers: WebView2 deployment friction, graph-viz performance shortfall, contributor-pattern signal. |
| 2026-05-03 | Custom URL scheme `lehen://oauth/callback` for desktop OAuth callbacks (Sprint 2) | localhost loopback redirect; web-page-with-paste-code | Standard pattern for desktop OAuth callbacks; matches project name; reserves `lehen://oauth/...` namespace for all future provider callbacks. |
| 2026-05-03 | Revoke-by-admin events visible to user by default with config flag escape hatch (Sprint 2) | Always silent; always visible no-flag | Privacy ethos in §7 demands transparency over what happens to the user's data. Hub config flag `admin.revoke_visibility = "visible" \| "silent"` permits per-deployment suppression for legitimate edge cases (works councils, regulatory contexts); default is `visible`. Audit trail records every admin action regardless. |

---

## Maintainer notes

This document captures the architectural commitments for v1. It is a living document — every change should be reflected with date and brief reason in the decisions log above. The discipline matters more than the elegance: when a contributor (or future-Sven) asks "why is it like this?", the answer should be findable in this file.
