"""Integration types registry and instance config schema.

In v1 the registry is hardcoded (see ``registry.py``). When real SourceAdapter
plugins land in a later journey, the registry becomes plugin-discovered and
this module's API stays the same.
"""

from lehen_hub.integrations.registry import (
    INTEGRATION_TYPES,
    FieldSpec,
    IntegrationType,
    UnknownIntegrationTypeError,
    get_type,
)

__all__ = [
    "INTEGRATION_TYPES",
    "FieldSpec",
    "IntegrationType",
    "UnknownIntegrationTypeError",
    "get_type",
]
