"""LLM provider registry — shared between admin UI rendering and LLM-config validation.

Same field-spec pattern as ``integrations.registry`` so the admin UI can render
both panes uniformly: a provider dropdown drives a dynamic field list, with
``secret=True`` fields rendered as password inputs and stored encrypted.
"""

from lehen_hub.llm.providers import (
    LLM_PROVIDERS,
    LLMProvider,
    LLMProviderFieldSpec,
    UnknownLLMProviderError,
    get_provider,
)

__all__ = [
    "LLM_PROVIDERS",
    "LLMProvider",
    "LLMProviderFieldSpec",
    "UnknownLLMProviderError",
    "get_provider",
]
