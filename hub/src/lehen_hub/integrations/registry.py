"""Hardcoded integration types registry for v1.

Each type declares its config schema as a list of ``FieldSpec``. Public fields
are stored in plaintext and returned in GET responses. Secret fields are
AES-256-GCM encrypted at rest and replaced by ``{is_set: bool, hmac: ...}``
markers in API responses + audit logs.

Three types ship in v1, matching the default SourceAdapters in DESIGN.md §6:
- ``outlook-com``       — Outlook Mail via Windows COM (Edge-local; no config)
- ``teams-graph``       — Microsoft Teams via Graph API (tenant-OAuth)
- ``itsm-rest-generic`` — generic ITSM REST adapter (configurable endpoint)

Real ``SourceAdapter`` implementations are out of scope for journey 1 — these
declarations only feed admin UI rendering and `IntegrationInstance` validation.
"""

from __future__ import annotations

from dataclasses import dataclass


class UnknownIntegrationTypeError(ValueError):
    """The given integration type id is not in the v1 registry."""


@dataclass(frozen=True)
class FieldSpec:
    """One config field of an integration type."""

    name: str
    label: str
    field_type: str  # "string" | "url" | "uuid" — extend as needed
    required: bool = False
    secret: bool = False
    placeholder: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class IntegrationType:
    id: str
    display_name: str
    description: str
    fields: tuple[FieldSpec, ...]

    @property
    def public_field_names(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if not f.secret)

    @property
    def secret_field_names(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if f.secret)


INTEGRATION_TYPES: tuple[IntegrationType, ...] = (
    IntegrationType(
        id="outlook-com",
        display_name="Microsoft Outlook (COM)",
        description=(
            "Outlook mail captured via Windows COM. The Edge consumes the existing "
            "Outlook session on the user's workstation; no central credentials needed."
        ),
        fields=(),
    ),
    IntegrationType(
        id="teams-graph",
        display_name="Microsoft Teams (Graph API)",
        description=(
            "Microsoft Teams via the Graph API with delegated user consent. "
            "Requires a registered Microsoft Entra application (tenant + client + secret)."
        ),
        fields=(
            FieldSpec(
                name="tenant_id",
                label="Microsoft Tenant ID",
                field_type="uuid",
                required=True,
                placeholder="00000000-0000-0000-0000-000000000000",
                description="The Microsoft Entra tenant id of the customer.",
            ),
            FieldSpec(
                name="client_id",
                label="Application (Client) ID",
                field_type="uuid",
                required=True,
                description="The client id of the registered Entra application.",
            ),
            FieldSpec(
                name="client_secret",
                label="Client Secret",
                field_type="string",
                required=True,
                secret=True,
                description="The client secret value from the Entra application.",
            ),
        ),
    ),
    IntegrationType(
        id="itsm-rest-generic",
        display_name="Generic ITSM (REST)",
        description=(
            "Generic ITSM REST adapter. Use for HP Service Manager, BMC, "
            "or any ITSM exposing a REST API + bearer-token / API-key auth."
        ),
        fields=(
            FieldSpec(
                name="base_url",
                label="ITSM Base URL",
                field_type="url",
                required=True,
                placeholder="https://itsm.company.example/api/v1",
            ),
            FieldSpec(
                name="api_key",
                label="API Key",
                field_type="string",
                required=True,
                secret=True,
            ),
        ),
    ),
)

_BY_ID: dict[str, IntegrationType] = {t.id: t for t in INTEGRATION_TYPES}


def get_type(type_id: str) -> IntegrationType:
    """Return the IntegrationType by id, or raise ``UnknownIntegrationTypeError``."""
    spec = _BY_ID.get(type_id)
    if spec is None:
        raise UnknownIntegrationTypeError(f"unknown integration type: {type_id}")
    return spec
