"""Idempotent admin-schema bootstrap.

On every Hub startup:
1. Ensure the configured database exists (creating it via the server-admin
   path so root has full schema permissions).
2. Create any of the seven admin document types that don't exist yet.
3. If ``LLMConfig`` is empty, seed the singleton row with hardcoded first-run
   defaults. After that, the admin UI is the only place this gets edited.

First-run defaults are deliberately hardcoded and have no env override path.
The previous ``LEHEN_ADMIN_BOOTSTRAP__*`` and ``LEHEN_OLLAMA__BASE_URL`` env
vars created a misleading appearance that ``.env`` was the live config when
in fact the DB was the source of truth. ``.env`` is now bootstrap-only;
LLMConfig is DB-only.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import structlog

from lehen_hub.storage.arcade import ArcadeClient

_DOC_TYPES = (
    "LLMConfig",
    "IntegrationInstance",
    "SIAMMapping",
    "IntegrationConnection",
    "ConsentEvent",
    "AdminAuditEvent",
    "LoginEvent",
    # Sprint 1.5 — local-admin bootstrap surface (separate audit class so ops
    # can alert on local-admin events independently from regular admin actions).
    "LocalAdmin",
    "LocalAdminLoginEvent",
    "LocalAdminCredentialRotated",
)

# First-run defaults for LLMConfig. Admin owns these via /admin/llm after the
# initial seed; nothing in the env can alter them at runtime.
_DEFAULT_OLLAMA_BASE_URL = "http://host.docker.internal:11434"
_DEFAULT_INFERENCE_MODEL = "gemma4:e4b"
_DEFAULT_EMBEDDING_MODEL = "nomic-embed-text"


async def ensure_admin_schema(
    client: ArcadeClient,
    *,
    now: datetime | None = None,
) -> list[str]:
    """Ensure database + document types exist + seed ``LLMConfig`` if empty.
    Idempotent.

    Returns names of newly-created types (empty list on subsequent boots).
    """
    log = structlog.get_logger(__name__)
    now = now or datetime.now(UTC)

    if not await client.database_exists():
        log.info("hub.admin.database_create", database=client.database)
        await client.server_command(f"CREATE DATABASE {client.database}")

    existing = {row.get("name") for row in await client.query("SELECT name FROM schema:types")}
    created: list[str] = []
    for type_name in _DOC_TYPES:
        if type_name in existing:
            continue
        await client.command(f"CREATE DOCUMENT TYPE {type_name} IF NOT EXISTS")
        created.append(type_name)

    log.info("hub.admin.bootstrap", created_types=created)

    if await _is_llm_config_empty(client):
        await _seed_llm_config(client, now=now)
        log.info(
            "hub.admin.llm_config.seeded",
            base_url=_DEFAULT_OLLAMA_BASE_URL,
            inference_model=_DEFAULT_INFERENCE_MODEL,
            embedding_model=_DEFAULT_EMBEDDING_MODEL,
        )

    return created


async def _is_llm_config_empty(client: ArcadeClient) -> bool:
    rows = await client.query("SELECT count(*) AS c FROM LLMConfig")
    if not rows:
        return True
    count = rows[0].get("c", 0)
    return int(count) == 0


async def _seed_llm_config(client: ArcadeClient, *, now: datetime) -> None:
    doc = {
        "id": "default",
        "inference_provider": "ollama",
        "inference_model": _DEFAULT_INFERENCE_MODEL,
        "inference_base_url": _DEFAULT_OLLAMA_BASE_URL,
        "embedding_provider": "ollama",
        "embedding_model": _DEFAULT_EMBEDDING_MODEL,
        "embedding_base_url": _DEFAULT_OLLAMA_BASE_URL,
        "updated_by": "system-bootstrap",
        "updated_at": now.isoformat(),
    }
    # doc dict is fully constructed from validated input — JSON literal embed is safe.
    await client.command(f"INSERT INTO LLMConfig CONTENT {json.dumps(doc)}")
