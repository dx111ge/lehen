"""``OutlookGraphAdapter`` + ``build_adapter_for_instance`` dispatch."""

from __future__ import annotations

import httpx
import pytest
import respx

from lehen_hub.integrations.source_adapter import (
    OutlookGraphAdapter,
    SourceAdapterError,
    SourceAdapterNotImplementedError,
    build_adapter_for_instance,
)


@pytest.fixture
async def http_client() -> httpx.AsyncClient:
    async with httpx.AsyncClient() as c:
        yield c


@pytest.fixture
def outlook_adapter() -> OutlookGraphAdapter:
    return OutlookGraphAdapter(tenant_id="tenant-abc")


class TestOutlookGraphEndpoints:
    def test_auth_endpoint_uses_tenant(
        self, outlook_adapter: OutlookGraphAdapter
    ) -> None:
        assert (
            outlook_adapter.auth_endpoint
            == "https://login.microsoftonline.com/tenant-abc/oauth2/v2.0/authorize"
        )

    def test_token_endpoint_uses_tenant(
        self, outlook_adapter: OutlookGraphAdapter
    ) -> None:
        assert (
            outlook_adapter.token_endpoint
            == "https://login.microsoftonline.com/tenant-abc/oauth2/v2.0/token"
        )

    def test_scopes_include_offline_access_for_refresh(
        self, outlook_adapter: OutlookGraphAdapter
    ) -> None:
        # offline_access is the Microsoft scope that triggers refresh_token
        # issuance — without it the OAuth flow yields a one-shot access token
        assert "offline_access" in outlook_adapter.scopes

    def test_scopes_include_mail_read_and_user_read(
        self, outlook_adapter: OutlookGraphAdapter
    ) -> None:
        assert "Mail.Read" in outlook_adapter.scopes
        assert "User.Read" in outlook_adapter.scopes

    def test_extra_authorization_params_force_consent(
        self, outlook_adapter: OutlookGraphAdapter
    ) -> None:
        # prompt=consent ensures re-consent when scopes change between sprints
        assert outlook_adapter.extra_authorization_params == {"prompt": "consent"}


class TestOutlookGraphFetchUserIdentity:
    @respx.mock
    async def test_returns_smtp_and_display_name(
        self,
        outlook_adapter: OutlookGraphAdapter,
        http_client: httpx.AsyncClient,
    ) -> None:
        respx.get("https://graph.microsoft.com/v1.0/me").mock(
            return_value=httpx.Response(
                200,
                json={
                    "mail": "alice@company.example",
                    "userPrincipalName": "alice@company.onmicrosoft.com",
                    "displayName": "Alice Adams",
                },
            )
        )
        external_subject, display_label = await outlook_adapter.fetch_user_identity(
            access_token="at-1", http_client=http_client
        )
        assert external_subject == "alice@company.example"
        assert display_label == "Alice Adams"

    @respx.mock
    async def test_falls_back_to_userPrincipalName_when_mail_null(  # noqa: N802
        self,
        outlook_adapter: OutlookGraphAdapter,
        http_client: httpx.AsyncClient,
    ) -> None:
        # Some personal Microsoft accounts return mail=null
        respx.get("https://graph.microsoft.com/v1.0/me").mock(
            return_value=httpx.Response(
                200,
                json={
                    "mail": None,
                    "userPrincipalName": "alice@company.onmicrosoft.com",
                    "displayName": "Alice Adams",
                },
            )
        )
        external_subject, _ = await outlook_adapter.fetch_user_identity(
            access_token="at-1", http_client=http_client
        )
        assert external_subject == "alice@company.onmicrosoft.com"

    @respx.mock
    async def test_raises_on_4xx(
        self,
        outlook_adapter: OutlookGraphAdapter,
        http_client: httpx.AsyncClient,
    ) -> None:
        respx.get("https://graph.microsoft.com/v1.0/me").mock(
            return_value=httpx.Response(401, json={"error": "invalid_token"})
        )
        with pytest.raises(SourceAdapterError, match="401"):
            await outlook_adapter.fetch_user_identity(
                access_token="bad", http_client=http_client
            )


class TestOutlookGraphHealth:
    @respx.mock
    async def test_health_ok_on_200(
        self,
        outlook_adapter: OutlookGraphAdapter,
        http_client: httpx.AsyncClient,
    ) -> None:
        respx.get("https://graph.microsoft.com/v1.0/me").mock(
            return_value=httpx.Response(
                200, json={"userPrincipalName": "alice@example.com"}
            )
        )
        assert await outlook_adapter.health(
            access_token="at-1", http_client=http_client
        ) is True

    @respx.mock
    async def test_health_fail_on_4xx(
        self,
        outlook_adapter: OutlookGraphAdapter,
        http_client: httpx.AsyncClient,
    ) -> None:
        respx.get("https://graph.microsoft.com/v1.0/me").mock(
            return_value=httpx.Response(401)
        )
        assert await outlook_adapter.health(
            access_token="bad", http_client=http_client
        ) is False


class TestAdapterDispatch:
    def test_outlook_graph_instance_returns_outlook_graph_adapter(self) -> None:
        instance = {
            "type": "outlook-graph",
            "config_public": {"tenant_id": "abc", "client_id": "cli"},
        }
        adapter = build_adapter_for_instance(instance)
        assert isinstance(adapter, OutlookGraphAdapter)

    def test_outlook_edge_com_raises_not_implemented(self) -> None:
        instance = {"type": "outlook-edge-com", "config_public": {}}
        with pytest.raises(SourceAdapterNotImplementedError):
            build_adapter_for_instance(instance)

    def test_teams_graph_raises_not_implemented_in_sprint_2(self) -> None:
        # teams-graph adapter ships in Sprint 3+
        instance = {
            "type": "teams-graph",
            "config_public": {"tenant_id": "abc", "client_id": "cli"},
        }
        with pytest.raises(SourceAdapterNotImplementedError):
            build_adapter_for_instance(instance)

    def test_unknown_type_raises_not_implemented(self) -> None:
        instance = {"type": "fake-source", "config_public": {}}
        with pytest.raises(SourceAdapterNotImplementedError):
            build_adapter_for_instance(instance)

    def test_outlook_graph_missing_tenant_id_raises(self) -> None:
        instance = {"type": "outlook-graph", "config_public": {}}
        with pytest.raises(SourceAdapterError, match="tenant_id"):
            build_adapter_for_instance(instance)
