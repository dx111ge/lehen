"""Application settings. All knobs come from env vars with the LEHEN_ prefix.

Nested settings use the double-underscore separator, e.g.:
    LEHEN_ARCADEDB__PASSWORD=...
    LEHEN_KEYCLOAK__BASE_URL=...
    LEHEN_CRYPTO__MASTER_KEY=...
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
    postgres_port: int = 5432
    user: str = "root"
    password: str
    database: str = "lehen"

    @property
    def http_url(self) -> str:
        return f"http://{self.host}:{self.http_port}"

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql://{self.user}:{self.password}"
            f"@{self.host}:{self.postgres_port}/{self.database}"
        )


class KeycloakSettings(BaseModel):
    base_url: str
    realm: str = "lehen"
    audience: str = "lehen-hub"
    admin_role: str = "lehen-admin"
    jwks_ttl_seconds: int = 600
    edge_client_id: str = "lehen-edge"
    admin_ui_client_id: str = "lehen-admin-ui"

    @property
    def issuer(self) -> str:
        return f"{self.base_url.rstrip('/')}/realms/{self.realm}"

    @property
    def well_known_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"

    @property
    def jwks_url(self) -> str:
        return f"{self.issuer}/protocol/openid-connect/certs"


class OllamaSettings(BaseModel):
    """Network-topology config for Ollama. Model selections live in the DB-backed
    LLMConfig (admin-mutable) — not here."""

    base_url: str = "http://host.docker.internal:11434"

    @property
    def tags_url(self) -> str:
        return f"{self.base_url.rstrip('/')}/api/tags"


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
    """Per-event-type retention windows. v1 writes ``retain_until`` at insert time
    using these defaults; cleanup task ships in v1.x (A11)."""

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

    env: str = "dev"
    log_level: str = "INFO"

    arcadedb: ArcadeDBSettings
    keycloak: KeycloakSettings
    crypto: CryptoSettings
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    retention: RetentionSettings = Field(default_factory=RetentionSettings)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
