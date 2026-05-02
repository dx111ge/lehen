"""Hardcoded LLM provider catalog.

Three providers ship in v1:

* ``ollama`` — local Ollama runtime; no API key.
* ``openai-compatible`` — any server speaking the OpenAI v1 API
  (vLLM, LM Studio, llama.cpp server, LiteLLM, ...). API key optional.
* ``openai`` — hosted OpenAI cloud. API key required.

The same provider catalog is consumed for both the inference side and the
embedding side. Whether a particular provider supports embeddings (vs.
inference only) is a deployment-time question we don't model here yet —
admins pick a provider per side and enter the model name they want.
"""

from __future__ import annotations

from dataclasses import dataclass


class UnknownLLMProviderError(ValueError):
    """The given LLM provider id is not in the registry."""


@dataclass(frozen=True)
class LLMProviderFieldSpec:
    name: str
    label: str
    field_type: str
    required: bool = False
    secret: bool = False
    placeholder: str | None = None
    description: str | None = None


@dataclass(frozen=True)
class LLMProvider:
    id: str
    display_name: str
    description: str
    fields: tuple[LLMProviderFieldSpec, ...]

    @property
    def public_field_names(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if not f.secret)

    @property
    def secret_field_names(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if f.secret)


LLM_PROVIDERS: tuple[LLMProvider, ...] = (
    LLMProvider(
        id="ollama",
        display_name="Ollama (local)",
        description=(
            "Local Ollama runtime on or near the Hub host. No API key. "
            "The model must be pulled into Ollama on the host first "
            "(e.g. `ollama pull gemma4:e4b`)."
        ),
        fields=(
            LLMProviderFieldSpec(
                name="base_url",
                label="Ollama URL",
                field_type="url",
                required=True,
                placeholder="http://host.docker.internal:11434",
                description="Where the Hub container can reach Ollama.",
            ),
            LLMProviderFieldSpec(
                name="model",
                label="Model",
                field_type="string",
                required=True,
                placeholder="gemma4:e4b",
                description="Ollama model tag — must already be pulled.",
            ),
        ),
    ),
    LLMProvider(
        id="openai-compatible",
        display_name="OpenAI-compatible (vLLM, LM Studio, …)",
        description=(
            "Any server speaking the OpenAI v1 chat/completions API: vLLM, "
            "LM Studio, LiteLLM, llama.cpp server, etc. Self-hosted servers "
            "often allow an empty API key; hosted ones require one."
        ),
        fields=(
            LLMProviderFieldSpec(
                name="base_url",
                label="API Base URL",
                field_type="url",
                required=True,
                placeholder="http://vllm.local:8000/v1",
                description=(
                    "The /v1 endpoint root of the OpenAI-compatible server."
                ),
            ),
            LLMProviderFieldSpec(
                name="model",
                label="Model",
                field_type="string",
                required=True,
                placeholder="meta-llama/Llama-3.1-8B-Instruct",
                description="Model identifier as expected by the server.",
            ),
            LLMProviderFieldSpec(
                name="api_key",
                label="API Key",
                field_type="string",
                required=False,
                secret=True,
                description=(
                    "Optional for self-hosted; required for managed services. "
                    "Stored AES-256-GCM-encrypted at rest in ArcadeDB."
                ),
            ),
        ),
    ),
    LLMProvider(
        id="openai",
        display_name="OpenAI (cloud)",
        description=(
            "Hosted OpenAI API. WARNING: this sends prompt content to OpenAI. "
            "Only enable if the customer's data-handling policy permits it; "
            "see docs/policy/scope-and-data-handling.md."
        ),
        fields=(
            LLMProviderFieldSpec(
                name="base_url",
                label="API Base URL",
                field_type="url",
                required=False,
                placeholder="https://api.openai.com/v1",
                description=(
                    "Override only for regional or proxy endpoints; "
                    "leave empty to use the default."
                ),
            ),
            LLMProviderFieldSpec(
                name="model",
                label="Model",
                field_type="string",
                required=True,
                placeholder="gpt-4o-mini",
            ),
            LLMProviderFieldSpec(
                name="api_key",
                label="API Key",
                field_type="string",
                required=True,
                secret=True,
                description=(
                    "Stored AES-256-GCM-encrypted at rest in ArcadeDB."
                ),
            ),
        ),
    ),
)

_BY_ID: dict[str, LLMProvider] = {p.id: p for p in LLM_PROVIDERS}


def get_provider(provider_id: str) -> LLMProvider:
    """Return the LLMProvider by id, or raise ``UnknownLLMProviderError``."""
    spec = _BY_ID.get(provider_id)
    if spec is None:
        raise UnknownLLMProviderError(f"unknown LLM provider: {provider_id}")
    return spec
