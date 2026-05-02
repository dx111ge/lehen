"""Idempotent admin-schema bootstrap.

On every Hub startup:
1. Ensure the configured database exists (creating it via the server-admin
   path so root has full schema permissions).
2. Create any of the seven admin document types that don't exist yet.
3. If ``LLMConfig`` is empty, seed the singleton row with hardcoded first-run
   defaults (``gemma4:e4b`` / ``nomic-embed-text``). After that, the admin
   UI is the only place this gets edited.

The first-run defaults are deliberately hardcoded rather than env-driven:
the previous ``LEHEN_ADMIN_BOOTSTRAP__*`` env vars created a confusing
appearance that ``.env`` was the live config when in fact the DB was the
source of truth and the env values were ignored after the first boot.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import structlog

from lehen_hub.config import OllamaSettings
from lehen_hub.storage.arcade import ArcadeClient

_DOC_TYPES = (
    "LLMConfig",
    "IntegrationInstance",
    "SIAMMapping",
    "IntegrationConnection",
    "ConsentEvent",
    "AdminAuditEvent",
    "LoginEvent",
)

# First-run defaults for LLMConfig. After the seed, the admin UI is the only
# place these get changed; env vars never override the DB.
_DEFAULT_INFERENCE_MODEL = "gemma4:e4b"
_DEFAULT_EMBEDDING_MODEL = "nomic-embed-text"


async def ensure_admin_schema(
    client: ArcadeClient,
    *,
    ollama: OllamaSettings,
    now: datetime | None = None,
) -> list[str]:
    """Ensure database + document types exist + seed ``LLMConfig`` if empty.
    Idempotent.

    Returns names of newly-created types (empty list on subsequent boots).
    """
    log = structlog.get_logger(__name__)
    now = now or datetime.now(UTC)

    if not await client.database_exists():
        # Creating the database via /api/v1/server (server-admin auth) makes
        # the root user the owner and grants full permissions including schema
        # updates. Required by ArcadeDB 26.x default security policy.
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
        await _seed_llm_config(client, ollama=ollama, now=now)
        log.info(
            "hub.admin.llm_config.seeded",
            base_url=ollama.base_url,
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


async def _seed_llm_config(
    client: ArcadeClient,
    *,
    ollama: OllamaSettings,
    now: datetime,
) -> None:
    doc = {
        "id": "default",
        "inference_provider": "ollama",
        "inference_model": _DEFAULT_INFERENCE_MODEL,
        "inference_base_url": ollama.base_url,
        "embedding_provider": "ollama",
        "embedding_model": _DEFAULT_EMBEDDING_MODEL,
        "embedding_base_url": ollama.base_url,
        "updated_by": "system-bootstrap",
        "updated_at": now.isoformat(),
    }
    # doc dict is fully constructed from validated input — JSON literal embed is safe.
    await client.command(f"INSERT INTO LLMConfig CONTENT {json.dumps(doc)}")
