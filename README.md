# Lehen

> Open-source on-premise knowledge platform that binds knowledge to roles, not people — captured as a side effect of normal work across mail, Teams, and ITSM.

**Status:** Phase 1 architecture defined, implementation not yet started. See [DESIGN.md](DESIGN.md) for the full architectural commitments.

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
|  Tauri app, Windows MSI    |  -------->   |  Docker / K8s         |
|  - Outlook COM connector   |   (no raw    |  - FastAPI server     |
|  - Teams Graph connector   |    content)  |  - ArcadeDB           |
|  - ITSM REST connector     |              |  - Ollama             |
|  - Local KB cache          |              |  - Keycloak           |
|  - Privacy filter          |              |                       |
+----------------------------+              +-----------------------+
```

Full architectural reasoning, plugin contracts, and decisions log are in [DESIGN.md](DESIGN.md).

## Technology

| Layer | Choice |
|-------|--------|
| Hub language | Python 3.12 + FastAPI |
| Hub deployment | Docker Compose / Helm chart |
| Edge language | Rust + Tauri v2 |
| Edge platforms (v1) | Windows only |
| Graph database | ArcadeDB (Postgres wire protocol) |
| LLM / Embeddings | Ollama (default), swappable through plugin interfaces |
| Identity | Keycloak (default), swappable through plugin interface |

## Quickstart

Implementation has not started. The repository currently contains architectural commitments only. A working Hub bring-up and Edge installer will follow in the first development sprint.

When implementation begins, the quickstart will be:

```bash
# Hub
cd hub
docker compose up

# Edge (Windows)
# Install lehen-edge-setup.msi from the releases page
```

## Contributing

Lehen is built as an open-source project with the explicit goal of community-built adapters for identity providers, ITSM connectors, and platform builds the maintainer cannot test in isolation. See [CONTRIBUTING.md](CONTRIBUTING.md) for high-impact wanted contributions and the plugin interface contracts.

## License

Lehen is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for the full text and [NOTICE](NOTICE) for trademark notice.

The "Lehen" name is a trademark of Sven Andreas. Forks and derivative works must operate under a different name. See [NOTICE](NOTICE) for the full trademark policy.

## Maintainer

Sven Andreas — [github.com/dx111ge](https://github.com/dx111ge)
