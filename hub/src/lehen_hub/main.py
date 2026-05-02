"""FastAPI app factory + lifespan + static SPA mounts.

Lifespan responsibilities:
1. Configure structlog.
2. Validate crypto keys (fail-closed if invalid).
3. Set up shared httpx.AsyncClient on app.state.http.
4. Set up + warm JWKSCache on app.state.jwks_cache.
5. Set up ArcadeClient on app.state.arcade.
6. Run idempotent admin schema bootstrap.
7. Wire up admin + user services on app.state.

Routers + mounts:
- /health/*           — liveness/readiness (existing)
- /auth/public-config — SPA OIDC discovery hint
- /me, /me/...        — user-side API
- /admin/*            — admin-side API (auth-gated at sub-app)
- /admin/             — admin SPA static files
- /app/               — user SPA static files
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import structlog
from fastapi import FastAPI, Request
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles

from lehen_hub import __version__
from lehen_hub.admin import (
    AdminAuditService,
    IntegrationsService,
    LLMService,
    SIAMService,
)
from lehen_hub.api.admin import router as admin_router
from lehen_hub.api.auth_config import router as auth_config_router
from lehen_hub.api.health import router as health_router
from lehen_hub.api.me import router as me_router
from lehen_hub.api.me_connections import router as me_connections_router
from lehen_hub.auth.jwks import JWKSCache
from lehen_hub.config import Settings, get_settings
from lehen_hub.logging import configure_logging
from lehen_hub.storage import ArcadeClient
from lehen_hub.storage.bootstrap import ensure_admin_schema
from lehen_hub.user import MeService, UserConnectionsService

_PACKAGE_DIR = Path(__file__).resolve().parent
_ADMIN_UI_DIR = _PACKAGE_DIR / "admin_ui"
_USER_UI_DIR = _PACKAGE_DIR / "user_ui"


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = get_settings()
    configure_logging(settings.log_level)
    log = structlog.get_logger()

    log.info(
        "hub.startup",
        env=settings.env,
        version=__version__,
        arcadedb_http=settings.arcadedb.http_url,
        keycloak_issuer=settings.keycloak.issuer,
        ollama=settings.ollama.base_url,
    )

    # 1. Validate crypto keys (fail-closed if pydantic validators didn't catch).
    master_key = settings.crypto.get_master_key_bytes()
    audit_pepper = settings.crypto.get_audit_pepper_bytes()
    log.info(
        "hub.crypto.key_loaded",
        master_key_len=len(master_key),
        audit_pepper_len=len(audit_pepper),
    )

    # 2. Shared httpx.AsyncClient for JWKS + ArcadeDB.
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(connect=5.0, read=15.0, write=15.0, pool=5.0)
    )
    app.state.http = http_client

    # 3. JWKS cache + warm.
    jwks_cache = JWKSCache(
        settings.keycloak.jwks_url,
        ttl_seconds=settings.keycloak.jwks_ttl_seconds,
    )
    await jwks_cache.warm(http_client)
    app.state.jwks_cache = jwks_cache
    log.info("hub.auth.jwks_warm", url=settings.keycloak.jwks_url)

    # 4. ArcadeDB client + idempotent admin schema bootstrap.
    arcade = ArcadeClient(settings=settings.arcadedb, http=http_client)
    app.state.arcade = arcade
    created = await ensure_admin_schema(arcade, ollama=settings.ollama)
    log.info("hub.admin.bootstrap.completed", created_types=created)

    # 5. Service singletons.
    admin_audit = AdminAuditService(arcade=arcade, audit_pepper=audit_pepper)
    app.state.admin_audit = admin_audit
    app.state.llm_service = LLMService(arcade=arcade, audit=admin_audit)
    app.state.integrations_service = IntegrationsService(
        arcade=arcade, audit=admin_audit, master_key=master_key
    )
    app.state.siam_service = SIAMService(arcade=arcade, audit=admin_audit)
    app.state.connections_service = UserConnectionsService(
        arcade=arcade,
        consent_retention_days=settings.retention.consent_event_days,
    )
    app.state.me_service = MeService(
        arcade=arcade,
        siam=app.state.siam_service,
        integrations=app.state.integrations_service,
        connections=app.state.connections_service,
        login_retention_days=settings.retention.login_event_days,
    )
    log.info("hub.services.ready")

    try:
        yield
    finally:
        await http_client.aclose()
        log.info("hub.shutdown")


def create_app() -> FastAPI:
    app = FastAPI(
        title="Lehen Hub",
        version=__version__,
        description="On-premise knowledge platform — Hub API",
        lifespan=lifespan,
    )

    @app.middleware("http")
    async def request_id_middleware(
        request: Request,
        call_next: Callable[[Request], Awaitable[Response]],
    ) -> Response:
        rid = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        request.state.request_id = rid
        response = await call_next(request)
        response.headers["X-Request-ID"] = rid
        return response

    app.include_router(health_router)
    app.include_router(auth_config_router)
    app.include_router(me_router)
    app.include_router(me_connections_router)
    app.include_router(admin_router)

    # Static SPA mounts. Explicit /admin/* API routes are matched first because
    # they were registered above; the mount is the catch-all for unmatched paths.
    if _ADMIN_UI_DIR.is_dir():
        app.mount(
            "/admin",
            StaticFiles(directory=_ADMIN_UI_DIR, html=True),
            name="admin_ui",
        )
    if _USER_UI_DIR.is_dir():
        app.mount(
            "/app",
            StaticFiles(directory=_USER_UI_DIR, html=True),
            name="user_ui",
        )

    return app


app = create_app()
