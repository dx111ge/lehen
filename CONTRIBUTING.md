# Contributing to Lehen

Lehen is an open-source project built around a deliberate plugin architecture. The maintainer (Sven Andreas) writes the core, the reference implementations, and the architectural commitments. **Many concrete adapters and platform builds are explicitly designed to be community contributions** — not because they are unimportant, but because they require access (e.g. Microsoft Entra ID tenants) or platform expertise (e.g. macOS Outlook) that the maintainer does not have.

If you want to contribute and you have such access or expertise, you are landing in exactly the right project.

## Project status

Phase 1 — architecture defined, implementation starting. See [DESIGN.md](DESIGN.md) for the architectural commitments. The codebase is in early bring-up; expect the structure of the repository, the build pipelines, and the plugin interfaces to stabilize over the next few weeks.

## High-impact wanted contributions

These are areas where the maintainer cannot make progress alone. Each is a real, valued contribution path with a documented interface contract.

| Area | Why wanted | Required access / expertise |
|------|------------|------------------------------|
| Microsoft Entra ID identity adapter | Default Keycloak is the reference; many enterprise customers run on Entra | Access to an Entra tenant for testing |
| Okta identity adapter | Same | Access to an Okta tenant |
| Auth0 / Ping / generic SAML adapters | Standard enterprise SAML providers | Access to the respective tenant |
| ServiceNow connector | One of the largest ITSM platforms; the maintainer's background is HP Service Manager | ServiceNow developer instance access |
| Jira / Atlassian connector | Common in mixed-stack environments | Atlassian Cloud or Data Center access |
| macOS Edge build | v1 is Windows-only; Mac requires a different mail-capture approach | Mac development environment, Outlook for Mac knowledge |
| Linux Edge build | Lower priority; Teams desktop on Linux discontinued 2023 | Linux development environment |
| Frontend framework selection inside the Tauri Edge | Choice between Svelte / Solid / React / others | Frontend expertise; preference matters |

If you intend to work on one of these, please open an issue first to coordinate with the maintainer and confirm the interface contract before significant code work.

## Plugin interface contracts

Lehen has five plugin interfaces. All replaceable components implement one of these. Default implementations ship in core; community contributions extend.

| Interface | Default | Methods |
|-----------|---------|---------|
| `SourceAdapter` | Outlook (COM), Teams (Graph), generic ITSM (REST) | `discover()`, `subscribe(filter)`, `fetch(id)`, `health()` |
| `EmbeddingProvider` | Ollama with `nomic-embed-text` | `embed(text) -> vector`, `dimensions()`, `health()` |
| `InferenceProvider` | Ollama with configurable model | `generate(prompt, params) -> stream`, `health()` |
| `IdentityProvider` | Keycloak via OIDC | `authenticate()`, `get_claims()`, `revoke()` |
| `PrivacyFilter` | Default rule-based + LLM check | `filter(payload) -> filtered_payload`, `audit_trail(filtered) -> record` |

Detailed specifications for each interface live in `docs/plugin-interfaces/`. New adapters should require **no** Lehen core changes — if they do, the interface is wrong and should be revised first.

## Development setup

(To be filled in as the build pipelines stabilize. Until then, expect breakage.)

### Hub

- Python 3.12+
- Package manager: `uv` (preferred) or `poetry`
- ArcadeDB via Docker
- Run: `docker compose up` from the `ops/` directory

### Edge

- Rust stable (1.80+)
- Tauri v2 prerequisites: <https://tauri.app/start/prerequisites/>
- Windows 10/11 with Outlook installed (for COM testing)

## Pull request process

1. Open an issue first to discuss the change, especially for new plugin adapters
2. Fork the repository and create a feature branch
3. Write tests — for plugin adapters, integration tests with the target system are required
4. Submit a PR with a clear description of what changed and why
5. The maintainer reviews; expect substantive feedback on architectural fit
6. Once merged, your contribution is under Apache 2.0 like the rest of the project

## Commit conventions

Conventional commits format is encouraged but not required:

```
feat(edge): add Outlook COM connector skeleton
fix(hub): correct ArcadeDB connection pooling
docs(design): clarify privacy filter location
```

## Code of conduct

Be direct, be constructive, be respectful. Disagreement is welcome; personal attacks are not. The maintainer holds himself to the same standard as he holds contributors.

## Communication

- **GitHub Issues** for bugs, feature requests, and adapter coordination
- **GitHub Discussions** for architectural questions and longer-form conversations
- **Maintainer contact** for trademark or licensing questions: see [NOTICE](NOTICE)

## License

By submitting a contribution, you agree that it will be licensed under the Apache License 2.0, the same license as the rest of the project. See [LICENSE](LICENSE).
