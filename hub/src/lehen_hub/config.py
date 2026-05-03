"""Application settings.

The ``.env`` is intentionally minimal — only what the bootstrap process
cannot function without:

* ArcadeDB connection (host/password/database) — required to read any DB
* Identity provider (Keycloak base URL + realm, **or** Entra tenant id +
  audience + client ids) — required to validate any JWT. The selector
  ``LEHEN_IDENTITY_PROVIDER`` picks which one is active; the corresponding
  block must be populated.
* Crypto master key + audit pepper — required to decrypt persisted secrets
  and HMAC the audit log

Everything else (LLM provider, model names, model URLs, log level, retention
windows, IdP audience/admin-role/client-ids) has a sensible default
in code and/or lives in the DB-backed ``LLMConfig`` document, which the
admin manages via ``/admin/*``. There is intentionally no shadow env knob
for any of those — that's the source of the "did I edit it in env or in
the admin UI?" confusion the v1 cleanup removed.
"""

from __future__ import annotations

import base64
import binascii
from functools import lru_cache
from typing import Literal

from pydantic import BaseModel, Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_KEY_LEN_BYTES = 32


def _validate_url_safe_b64_32_bytes(value: SecretStr) -> SecretStr:
    """Reused validator: ensures a SecretStr decodes from url-safe base64 to exactly 32 bytes."""
    raw_str = value.get_secret_value()
    try:
        decoded = base64.urlsafe_b64decode(raw_str.encode("ascii"))
    except (ValueError, binascii.Error) as exc:
        raise ValueError(f"not valid url-safe base64: {exc}") from exc
    if len(decoded) != _KEY_LEN_BYTES:
        raise ValueError(f"must decode to {_KEY_LEN_BYTES} bytes (got {len(decoded)})")
    return value


def _validate_optional_url_safe_b64_32_bytes(
    value: SecretStr | None,
) -> SecretStr | None:
    if value is None:
        return None
    return _validate_url_safe_b64_32_bytes(value)


class ArcadeDBSettings(BaseModel):
    host: str = "arcadedb"
    http_port: int = 2480
    user: str = "root"
    password: str
    database: str = "lehen"

    @property
    def http_url(self) -> str:
        return f"http://{self.host}:{self.http_port}"


class KeycloakSettings(BaseModel):
    """Keycloak topology + the few values the bootstrap path needs.

    ``base_url`` is required (no default) — without it the Hub cannot fetch
    JWKS and therefore cannot validate any token. The remaining fields
    (audience, admin role name, client ids, JWKS TTL) have stable defaults
    that match this codebase's other expectations; override only when you
    really mean it.
    """

    base_url: str
    realm: str = "lehen"
    audience: str = "lehen-hub"
    admin_role: str = "lehen-admin"
    edge_client_id: str = "lehen-edge"
    admin_ui_client_id: str = "lehen-admin-ui"
    jwks_ttl_seconds: int = 600

    @property
    def issuer(self) -> str:
        return f"{self.base_url.rstrip('/')}/realms/{self.realm}"

    @property
    def well_known_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"


class EntraSettings(BaseModel):
    """Microsoft Entra ID (Azure AD) topology.

    ``tenant_id`` is the customer's Entra tenant id. ``audience`` must match
    what the Entra app registration issues access tokens for — typically
    ``api://{client_id}`` once an API is exposed, sometimes plain ``{client_id}``
    for older app configurations. The operator picks this value to match
    their app registration; both forms are valid Entra issuance patterns.

    ``edge_client_id`` and ``admin_ui_client_id`` are the public client ids
    Edge and the admin SPA use for OIDC PKCE sign-in. In a single-app
    registration setup all three (audience source, edge, admin) can map to
    the same client_id with different scopes.

    Roles are read from the top-level ``roles`` claim — Entra emits this
    when the app manifest defines app roles assigned to the user. There is
    no ``realm_access`` shape on Entra tokens.
    """

    tenant_id: str
    audience: str
    admin_role: str = "lehen-admin"
    edge_client_id: str
    admin_ui_client_id: str
    jwks_ttl_seconds: int = 600

    @property
    def issuer(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/v2.0"

    @property
    def well_known_url(self) -> str:
        return (
            f"https://login.microsoftonline.com/{self.tenant_id}/v2.0/"
            ".well-known/openid-configuration"
        )

    @property
    def jwks_url(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}/discovery/v2.0/keys"


class LocalAdminSettings(BaseModel):
    """Local-admin bootstrap and break-glass settings.

    The local-admin path exists only to solve two problems: (a) a fresh Hub
    has no SIAM IdP configured yet, so an admin can't sign in via SSO; and
    (b) emergency access when SIAM is broken. It is auto-disabled on the
    first successful SIAM admin login and is invisible to the Edge surface.

    ``signing_key`` is required when local-admin is enabled. It is the HS256
    secret used by the Hub to sign its own JWTs (``iss=lehen-hub-local``).
    These tokens are validated only on the admin surface; user endpoints
    reject them outright by issuer claim.

    Generate the key with::

        python -c "import secrets,base64; \\
          print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
    """

    enabled: bool = True
    signing_key: SecretStr | None = None
    token_ttl_seconds: int = 3600  # 1 hour
    failed_attempts_threshold: int = 10  # Lockout after this many failures
    lockout_duration_seconds: int = 900  # 15 minutes
    rate_limit_per_minute: int = 5  # Per IP, per username

    _validate_signing_key = field_validator("signing_key")(
        _validate_optional_url_safe_b64_32_bytes
    )

    def get_signing_key_bytes(self) -> bytes:
        if self.signing_key is None:
            raise ValueError("local-admin signing_key is not configured")
        return base64.urlsafe_b64decode(
            self.signing_key.get_secret_value().encode("ascii")
        )


class CryptoSettings(BaseModel):
    """Master key + audit pepper. Both required, validated to be 32 bytes after
    url-safe base64 decode.

    Generate either with::

        python -c "import secrets,base64; \\
          print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode())"
    """

    master_key: SecretStr
    audit_pepper: SecretStr

    _validate_master_key = field_validator("master_key")(_validate_url_safe_b64_32_bytes)
    _validate_audit_pepper = field_validator("audit_pepper")(_validate_url_safe_b64_32_bytes)

    def get_master_key_bytes(self) -> bytes:
        return base64.urlsafe_b64decode(self.master_key.get_secret_value().encode("ascii"))

    def get_audit_pepper_bytes(self) -> bytes:
        return base64.urlsafe_b64decode(self.audit_pepper.get_secret_value().encode("ascii"))


class RetentionSettings(BaseModel):
    """Per-event-type retention windows.

    Defaults live in code and are not surfaced in .env.example or the compose
    file — retention is intended to move to admin-configured DB state when the
    cleanup task ships (A11). For the rare case where a deployment needs a
    different number before that, the env path
    ``LEHEN_RETENTION__LOGIN_EVENT_DAYS`` / ``LEHEN_RETENTION__CONSENT_EVENT_DAYS``
    still works (pydantic-settings nested env), but it's not advertised.
    """

    login_event_days: int = 90
    consent_event_days: int = 2557  # ~7 years; legal-proof default for consent records


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="LEHEN_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # Stable defaults; not env-driven. Override at the entrypoint if needed.
    env: str = "dev"
    log_level: str = "INFO"

    arcadedb: ArcadeDBSettings
    crypto: CryptoSettings
    retention: RetentionSettings = Field(default_factory=RetentionSettings)
    local_admin: LocalAdminSettings = Field(default_factory=LocalAdminSettings)

    # OAuth redirect-URI allowlist for SourceAdapter flows. Comma-separated
    # in env (``LEHEN_OAUTH_ALLOWED_REDIRECT_URIS``). Default covers the
    # Edge's custom URL scheme; production deployments add their own values.
    oauth_allowed_redirect_uris: list[str] = Field(
        default_factory=lambda: ["lehen://oauth/callback"]
    )

    # Identity provider selector + per-provider config blocks. Exactly one
    # provider is active per Hub deployment; both blocks may be populated in
    # dev for switching between them via ``LEHEN_IDENTITY_PROVIDER``.
    identity_provider: Literal["keycloak", "entra"] = "keycloak"
    keycloak: KeycloakSettings | None = None
    entra: EntraSettings | None = None

    @model_validator(mode="after")
    def _selected_provider_is_configured(self) -> Settings:
        if self.identity_provider == "keycloak" and self.keycloak is None:
            raise ValueError(
                "identity_provider=keycloak but LEHEN_KEYCLOAK__BASE_URL "
                "(and any other keycloak fields) are not set"
            )
        if self.identity_provider == "entra" and self.entra is None:
            raise ValueError(
                "identity_provider=entra but LEHEN_ENTRA__TENANT_ID, "
                "LEHEN_ENTRA__AUDIENCE, LEHEN_ENTRA__EDGE_CLIENT_ID, "
                "LEHEN_ENTRA__ADMIN_UI_CLIENT_ID are not all set"
            )
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
