"""IdentityProvider implementations — discovery surface and role extraction
for both Keycloak and Entra. Each provider's role-extraction is tested
against the *other* provider's claim shape to verify there's no silent
cross-provider impersonation if both were ever configured side-by-side."""

from __future__ import annotations

import pytest

from lehen_hub.auth.identity_provider import (
    EntraIdentityProvider,
    IdentityProvider,
    KeycloakIdentityProvider,
    build_identity_provider_from_settings,
)
from lehen_hub.config import EntraSettings, KeycloakSettings

TEST_TENANT_ID = "00000000-0000-0000-0000-000000000abc"


@pytest.fixture
def keycloak_settings() -> KeycloakSettings:
    return KeycloakSettings(
        base_url="http://test-keycloak:8080",
        realm="test-realm",
    )


@pytest.fixture
def entra_settings() -> EntraSettings:
    return EntraSettings(
        tenant_id=TEST_TENANT_ID,
        audience=f"api://{TEST_TENANT_ID}-client",
        edge_client_id=f"{TEST_TENANT_ID}-edge",
        admin_ui_client_id=f"{TEST_TENANT_ID}-admin-ui",
    )


class TestKeycloakIdentityProviderShape:
    def test_satisfies_protocol(self, keycloak_settings: KeycloakSettings) -> None:
        provider = KeycloakIdentityProvider(keycloak_settings)
        assert isinstance(provider, IdentityProvider)

    def test_provider_id(self, keycloak_settings: KeycloakSettings) -> None:
        provider = KeycloakIdentityProvider(keycloak_settings)
        assert provider.provider_id == "keycloak"

    def test_oidc_topology_derived_from_settings(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        provider = KeycloakIdentityProvider(keycloak_settings)
        assert provider.issuer == "http://test-keycloak:8080/realms/test-realm"
        assert (
            provider.well_known_url
            == "http://test-keycloak:8080/realms/test-realm/.well-known/openid-configuration"
        )
        assert (
            provider.jwks_url
            == "http://test-keycloak:8080/realms/test-realm/protocol/openid-connect/certs"
        )
        assert provider.audience == "lehen-hub"
        assert provider.admin_role == "lehen-admin"


class TestKeycloakRoleExtraction:
    def test_extracts_realm_access_roles(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        provider = KeycloakIdentityProvider(keycloak_settings)
        roles = provider.extract_realm_roles(
            {"realm_access": {"roles": ["change-manager", "lehen-admin"]}}
        )
        assert roles == ["change-manager", "lehen-admin"]

    def test_missing_realm_access_returns_empty(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        provider = KeycloakIdentityProvider(keycloak_settings)
        assert provider.extract_realm_roles({}) == []

    def test_realm_access_without_roles_returns_empty(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        provider = KeycloakIdentityProvider(keycloak_settings)
        assert provider.extract_realm_roles({"realm_access": {}}) == []

    def test_malformed_realm_access_returns_empty(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        # A token with realm_access as a string (not a dict) is well-formed JWT
        # but malformed for our purposes — treat as no roles, do not raise.
        provider = KeycloakIdentityProvider(keycloak_settings)
        assert provider.extract_realm_roles({"realm_access": "not-a-dict"}) == []

    def test_non_list_roles_returns_empty(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        provider = KeycloakIdentityProvider(keycloak_settings)
        assert (
            provider.extract_realm_roles(
                {"realm_access": {"roles": "single-string"}}
            )
            == []
        )

    def test_ignores_top_level_roles_claim(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        # Entra-shaped tokens carry roles at the top level. Keycloak adapter
        # must not pick those up — that would silently let an Entra token
        # impersonate a Keycloak user if both providers were configured.
        provider = KeycloakIdentityProvider(keycloak_settings)
        roles = provider.extract_realm_roles(
            {"roles": ["should-not-be-seen"], "realm_access": {"roles": ["real"]}}
        )
        assert roles == ["real"]


class TestKeycloakDiscoveryConfig:
    def test_includes_provider_id(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        config = KeycloakIdentityProvider(keycloak_settings).discovery_config()
        assert config["provider"] == "keycloak"

    def test_includes_oidc_topology(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        config = KeycloakIdentityProvider(keycloak_settings).discovery_config()
        assert config["issuer"] == "http://test-keycloak:8080/realms/test-realm"
        assert (
            config["well_known_url"]
            == "http://test-keycloak:8080/realms/test-realm/.well-known/openid-configuration"
        )
        assert config["audience"] == "lehen-hub"

    def test_includes_public_client_ids(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        config = KeycloakIdentityProvider(keycloak_settings).discovery_config()
        assert config["edge_client_id"] == "lehen-edge"
        assert config["admin_ui_client_id"] == "lehen-admin-ui"

    def test_does_not_leak_settings_internals(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        config = KeycloakIdentityProvider(keycloak_settings).discovery_config()
        # The discovery payload is unauthenticated; nothing here should
        # reveal more than what an OIDC discovery endpoint already does.
        assert "jwks_url" not in config  # JWKS is fetched server-side, not exposed
        assert "admin_role" not in config  # admin role name is not public knowledge


class TestEntraIdentityProviderShape:
    def test_satisfies_protocol(self, entra_settings: EntraSettings) -> None:
        provider = EntraIdentityProvider(entra_settings)
        assert isinstance(provider, IdentityProvider)

    def test_provider_id(self, entra_settings: EntraSettings) -> None:
        assert EntraIdentityProvider(entra_settings).provider_id == "entra"

    def test_oidc_topology_derived_from_tenant_id(
        self, entra_settings: EntraSettings
    ) -> None:
        provider = EntraIdentityProvider(entra_settings)
        assert (
            provider.issuer
            == f"https://login.microsoftonline.com/{TEST_TENANT_ID}/v2.0"
        )
        assert (
            provider.well_known_url
            == f"https://login.microsoftonline.com/{TEST_TENANT_ID}/v2.0/"
            ".well-known/openid-configuration"
        )
        assert (
            provider.jwks_url
            == f"https://login.microsoftonline.com/{TEST_TENANT_ID}/discovery/v2.0/keys"
        )
        assert provider.audience == f"api://{TEST_TENANT_ID}-client"
        assert provider.admin_role == "lehen-admin"


class TestEntraRoleExtraction:
    def test_extracts_top_level_roles(self, entra_settings: EntraSettings) -> None:
        provider = EntraIdentityProvider(entra_settings)
        roles = provider.extract_realm_roles(
            {"roles": ["change-manager", "lehen-admin"]}
        )
        assert roles == ["change-manager", "lehen-admin"]

    def test_missing_roles_returns_empty(self, entra_settings: EntraSettings) -> None:
        assert EntraIdentityProvider(entra_settings).extract_realm_roles({}) == []

    def test_non_list_roles_returns_empty(
        self, entra_settings: EntraSettings
    ) -> None:
        provider = EntraIdentityProvider(entra_settings)
        assert provider.extract_realm_roles({"roles": "single-string"}) == []

    def test_ignores_realm_access_claim(self, entra_settings: EntraSettings) -> None:
        # Keycloak-shaped tokens carry roles in realm_access.roles. The Entra
        # adapter must not pick those up — that would silently let a Keycloak
        # token confer Entra-side authority if both providers were configured.
        provider = EntraIdentityProvider(entra_settings)
        roles = provider.extract_realm_roles(
            {
                "realm_access": {"roles": ["should-not-be-seen"]},
                "roles": ["real"],
            }
        )
        assert roles == ["real"]

    def test_keycloak_shape_token_yields_no_entra_roles(
        self, entra_settings: EntraSettings
    ) -> None:
        # A pure Keycloak-shaped token (no top-level `roles` claim) produces
        # an empty role list when fed to the Entra adapter — no impersonation.
        provider = EntraIdentityProvider(entra_settings)
        keycloak_shape = {"realm_access": {"roles": ["lehen-admin"]}}
        assert provider.extract_realm_roles(keycloak_shape) == []


class TestEntraDiscoveryConfig:
    def test_includes_provider_id(self, entra_settings: EntraSettings) -> None:
        config = EntraIdentityProvider(entra_settings).discovery_config()
        assert config["provider"] == "entra"

    def test_realm_field_carries_tenant_id(
        self, entra_settings: EntraSettings
    ) -> None:
        # Keep the response shape stable across providers — clients that read
        # `realm` get the tenant id for Entra; `provider` disambiguates.
        config = EntraIdentityProvider(entra_settings).discovery_config()
        assert config["realm"] == TEST_TENANT_ID

    def test_includes_oidc_topology(self, entra_settings: EntraSettings) -> None:
        config = EntraIdentityProvider(entra_settings).discovery_config()
        assert (
            config["issuer"]
            == f"https://login.microsoftonline.com/{TEST_TENANT_ID}/v2.0"
        )
        assert config["audience"] == f"api://{TEST_TENANT_ID}-client"
        assert config["edge_client_id"] == f"{TEST_TENANT_ID}-edge"


class TestProviderBuilder:
    def test_builds_keycloak_when_selected(
        self,
        keycloak_settings: KeycloakSettings,
        entra_settings: EntraSettings,
    ) -> None:
        # Both blocks populated — selector wins
        provider = build_identity_provider_from_settings(
            keycloak=keycloak_settings,
            entra=entra_settings,
            selector="keycloak",
        )
        assert provider.provider_id == "keycloak"

    def test_builds_entra_when_selected(
        self,
        keycloak_settings: KeycloakSettings,
        entra_settings: EntraSettings,
    ) -> None:
        provider = build_identity_provider_from_settings(
            keycloak=keycloak_settings,
            entra=entra_settings,
            selector="entra",
        )
        assert provider.provider_id == "entra"

    def test_keycloak_selected_but_settings_missing(
        self, entra_settings: EntraSettings
    ) -> None:
        with pytest.raises(RuntimeError, match="keycloak settings"):
            build_identity_provider_from_settings(
                keycloak=None,
                entra=entra_settings,
                selector="keycloak",
            )

    def test_entra_selected_but_settings_missing(
        self, keycloak_settings: KeycloakSettings
    ) -> None:
        with pytest.raises(RuntimeError, match="entra settings"):
            build_identity_provider_from_settings(
                keycloak=keycloak_settings,
                entra=None,
                selector="entra",
            )

    def test_unknown_selector_rejected(
        self,
        keycloak_settings: KeycloakSettings,
        entra_settings: EntraSettings,
    ) -> None:
        with pytest.raises(RuntimeError, match="unknown identity_provider"):
            build_identity_provider_from_settings(
                keycloak=keycloak_settings,
                entra=entra_settings,
                selector="okta",
            )
