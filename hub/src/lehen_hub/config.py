"""Application settings.

The ``.env`` is intentionally minimal — only what the bootstrap process
cannot function without:

* ArcadeDB connection (host/password/database) — required to read any DB
* Keycloak base URL + realm — required to validate any JWT
* Crypto master key + audit pepper — required to decrypt persisted secrets
  and HMAC the audit log

Everything else (LLM provider, model names, model URLs, log level, retention
windows, Keycloak audience/admin-role/client-ids) has a sensible default
in code and/or lives in the DB-backed ``LLMConfig`` document, which the
admin manages via ``/admin/*``. There is intentionally no shadow env knob
for any of those — that's the source of the "did I edit it in env or in
the admin UI?" confusion the v1 cleanup removed.
"""

from __future__ import annotations

import base64
import binascii
from functools import lru_cache

from pydantic import BaseModel, Field, SecretStr, field_validator
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
    keycloak: KeycloakSettings
    crypto: CryptoSettings
    retention: RetentionSettings = Field(default_factory=RetentionSettings)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
