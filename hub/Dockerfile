# syntax=docker/dockerfile:1.7
ARG UV_VERSION=0.11.8
ARG PYTHON_VERSION=3.12

# ============================================================================
# uv-bin — version-pinned uv binaries; copied into base stage below.
# (Combined uv+python tags ended at 0.5.9, so we use the binary-only image.)
# ============================================================================
FROM ghcr.io/astral-sh/uv:${UV_VERSION} AS uv-bin

# ============================================================================
# base — official Python + pinned uv
# ============================================================================
FROM python:${PYTHON_VERSION}-slim-bookworm AS base
COPY --from=uv-bin /uv /uvx /bin/
ENV UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    UV_PROJECT_ENVIRONMENT=/app/.venv \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}"
WORKDIR /app
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --create-home --shell /usr/sbin/nologin app

# ============================================================================
# deps — install dependencies into a cached layer (no project src yet)
# ============================================================================
FROM base AS deps
COPY --chown=app:app pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project

# ============================================================================
# dev — hot-reload target. src is bind-mounted at runtime, not baked in.
# ============================================================================
FROM deps AS dev
ENV PYTHONPATH=/app/src
RUN chown -R app:app /app
USER app
EXPOSE 8000
CMD ["uvicorn", "lehen_hub.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8000", \
     "--reload", \
     "--reload-dir", "/app/src"]

# ============================================================================
# prod — src baked in, project installed, dev deps excluded.
# ============================================================================
FROM base AS prod
COPY --chown=app:app pyproject.toml uv.lock ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev
COPY --chown=app:app src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev
USER app
EXPOSE 8000
CMD ["uvicorn", "lehen_hub.main:app", "--host", "0.0.0.0", "--port", "8000"]
