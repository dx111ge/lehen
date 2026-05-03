"""AdminAuditService — secret-field HMAC fingerprinting (A12)."""

from __future__ import annotations

import json
import secrets as stdlib_secrets

import httpx
import pytest
import respx

from lehen_hub.admin.audit_service import AdminAuditService, AuditEvent
from lehen_hub.config import ArcadeDBSettings
from lehen_hub.crypto import fingerprint
from lehen_hub.storage.arcade import ArcadeClient

ARCADE_URL = "http://test-arcade:2480/api/v1/command/lehen-test"


@pytest.fixture
def pepper() -> bytes:
    return stdlib_secrets.token_bytes(32)


@pytest.fixture
async def http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture
def arcade(http_client: httpx.AsyncClient) -> ArcadeClient:
    return ArcadeClient(
        settings=ArcadeDBSettings(
            host="test-arcade",
            password="test",
            database="lehen-test",
        ),
        http=http_client,
    )


@pytest.fixture
def service(arcade: ArcadeClient, pepper: bytes) -> AdminAuditService:
    return AdminAuditService(arcade=arcade, audit_pepper=pepper)


def _captured_doc(route: respx.Route) -> dict:
    """Pull the CONTENT json out of the INSERT command."""
    body = json.loads(route.calls[0].request.content.decode())
    cmd = body["command"]
    # 'INSERT INTO X CONTENT {json}'
    json_start = cmd.index("CONTENT ") + len("CONTENT ")
    return json.loads(cmd[json_start:])


@respx.mock
async def test_record_with_no_secret_fields_passes_through(
    service: AdminAuditService,
) -> None:
    route = respx.post(ARCADE_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    await service.record(
        AuditEvent(
            actor_sub="user-1",
            actor_username="dx",
            action="llm.update",
            target_id="default",
            before={"inference_model": "old-model"},
            after={"inference_model": "new-model"},
        )
    )
    doc = _captured_doc(route)
    assert doc["before"] == {"inference_model": "old-model"}
    assert doc["after"] == {"inference_model": "new-model"}


@respx.mock
async def test_record_replaces_secret_fields_with_hmac(
    service: AdminAuditService,
    pepper: bytes,
) -> None:
    route = respx.post(ARCADE_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    await service.record(
        AuditEvent(
            actor_sub="user-1",
            actor_username="dx",
            action="integration.create",
            target_id="teams-prod",
            before=None,
            after={
                "id": "teams-prod",
                "tenant_id": "abc-tenant",
                "client_secret": "super-secret-xyz",
            },
            secret_fields=("client_secret",),
        )
    )
    doc = _captured_doc(route)
    # Public fields are visible
    assert doc["after"]["id"] == "teams-prod"
    assert doc["after"]["tenant_id"] == "abc-tenant"
    # Secret field replaced by HMAC marker
    assert doc["after"]["client_secret"] == {
        "is_set": True,
        "hmac": fingerprint("super-secret-xyz", pepper=pepper),
    }


@respx.mock
async def test_same_secret_value_produces_same_hmac(
    service: AdminAuditService,
    pepper: bytes,
) -> None:
    route = respx.post(ARCADE_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    for _ in range(2):
        await service.record(
            AuditEvent(
                actor_sub="user-1",
                actor_username="dx",
                action="integration.update",
                target_id="x",
                before=None,
                after={"client_secret": "same-secret"},
                secret_fields=("client_secret",),
            )
        )
    docs = [
        json.loads(call.request.content.decode())["command"]
        for call in route.calls
    ]
    hmacs = [
        json.loads(d[d.index("CONTENT ") + len("CONTENT ") :])["after"]["client_secret"]["hmac"]
        for d in docs
    ]
    assert hmacs[0] == hmacs[1]
    assert hmacs[0] == fingerprint("same-secret", pepper=pepper)


@respx.mock
async def test_empty_secret_value_marked_unset(service: AdminAuditService) -> None:
    route = respx.post(ARCADE_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    await service.record(
        AuditEvent(
            actor_sub="user-1",
            actor_username="dx",
            action="integration.update",
            target_id="x",
            before={"client_secret": ""},
            after={"client_secret": None},
            secret_fields=("client_secret",),
        )
    )
    doc = _captured_doc(route)
    assert doc["before"]["client_secret"] == {"is_set": False, "hmac": None}
    assert doc["after"]["client_secret"] == {"is_set": False, "hmac": None}


@respx.mock
async def test_record_writes_required_meta(service: AdminAuditService) -> None:
    route = respx.post(ARCADE_URL).mock(return_value=httpx.Response(200, json={"result": []}))
    await service.record(
        AuditEvent(
            actor_sub="user-99",
            actor_username="dx-admin",
            action="siam.update",
            target_id="default",
            before=None,
            after={"mapping": {}},
            request_id="req-123",
        )
    )
    doc = _captured_doc(route)
    assert doc["actor_sub"] == "user-99"
    assert doc["actor_username"] == "dx-admin"
    assert doc["action"] == "siam.update"
    assert doc["request_id"] == "req-123"
    assert "ts" in doc
    assert "id" in doc
