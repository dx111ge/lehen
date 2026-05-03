"""Local-admin bootstrap and break-glass authentication path.

Strict scope rules — load-bearing:

* Single bootstrap admin per Hub install (the CLI overwrites the row on every
  re-run). No multi-admin local accounts.
* Password regenerated on every CLI re-run; the previous password is
  permanently invalidated by the overwrite.
* Auto-disable on first successful SIAM admin login. Re-enabling for an
  emergency requires re-running the bootstrap CLI on the Hub host.
* Hub-self-issued JWTs (``iss=lehen-hub-local``, ``scope=admin``) are valid
  ONLY on ``/admin/*`` endpoints. The user-surface auth dependency rejects
  them by issuer claim.

Threat-model accepted: anyone with shell access to the Hub host can rotate
the bootstrap password and authenticate. This is the same level of access
that `docker compose down && rm -rf` already grants. The local-admin path
does not weaken the existing security posture; it just makes operational
recovery possible without bypassing the abstraction.
"""

from __future__ import annotations

import contextlib
import json
import secrets
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

import structlog
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

from lehen_hub.auth.local_jwt import issue_local_admin_token
from lehen_hub.storage.arcade import ArcadeClient

_BOOTSTRAP_USERNAME = "admin"  # Single fixed bootstrap admin per Hub install

# Password used to absorb timing when the requested username doesn't exist.
# Verified against a real argon2 hash so the response time matches the
# success path; the comparison always fails and never produces a token.
_DUMMY_PASSWORD = "x"  # noqa: S105 — fixed dummy, never grants access

# argon2id parameters — OWASP 2024 baseline for interactive auth.
_HASHER = PasswordHasher(
    time_cost=3,
    memory_cost=64 * 1024,  # 64 MB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)
_DUMMY_HASH = _HASHER.hash(_DUMMY_PASSWORD)


class LocalAdminAuthError(Exception):
    """Authentication failed. Detail is intentionally vague — never reveal
    whether it was a wrong username, wrong password, or lockout."""


class LocalAdminLockedError(LocalAdminAuthError):
    """Account is currently locked out. Distinct exception so callers can
    decide whether to surface this state. Default behavior: do not."""


class LocalAdminDisabledError(LocalAdminAuthError):
    """Local-admin account is disabled (auto-disabled after first SIAM admin
    login, or never enabled). Distinct exception so the bootstrap flow can
    surface it; the login endpoint reports the same vague auth-failed reply."""


class LocalAdminNotConfiguredError(RuntimeError):
    """The local-admin signing key is missing from settings. The path is
    structurally unavailable until ``LEHEN_LOCAL_ADMIN__SIGNING_KEY`` is set."""


@dataclass(frozen=True)
class LocalAdminLoginResult:
    """Returned on a successful local-admin login."""

    token: str
    expires_at: datetime
    username: str


class _SlidingWindowCounter:
    """Per-key sliding-window rate limiter held in memory per process.

    Multi-replica Hubs would lose precision (each replica has its own
    counter), but the local-admin path is "rare emergency use" — per-replica
    rate limits remain a meaningful brake. State is intentionally not
    persisted; restart resets the windows.
    """

    def __init__(self, *, limit_per_minute: int) -> None:
        self._limit = limit_per_minute
        self._events: dict[str, list[float]] = defaultdict(list)

    def hit_and_check(self, key: str, *, now: float | None = None) -> bool:
        """Record a hit and return True if under the limit, False if over."""
        ts = now if now is not None else time.monotonic()
        cutoff = ts - 60.0
        bucket = self._events[key]
        bucket[:] = [e for e in bucket if e >= cutoff]
        bucket.append(ts)
        return len(bucket) <= self._limit


class LocalAdminService:
    """Owns the local-admin DB row, lockout state, JWT issuance, and audit.

    Constructed with an ``ArcadeClient`` and ``LocalAdminSettings``. The
    signing key is read once at construction; rotating it requires a Hub
    restart (intentional — the key sits at the trust root of all
    Hub-self-issued JWTs).
    """

    def __init__(
        self,
        *,
        arcade: ArcadeClient,
        signing_key: bytes,
        token_ttl_seconds: int,
        failed_attempts_threshold: int,
        lockout_duration_seconds: int,
        rate_limit_per_minute: int,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._arcade = arcade
        self._signing_key = signing_key
        self._token_ttl = token_ttl_seconds
        self._failed_threshold = failed_attempts_threshold
        self._lockout_duration = lockout_duration_seconds
        self._rate_limit = _SlidingWindowCounter(limit_per_minute=rate_limit_per_minute)
        self._log = structlog.get_logger(__name__)
        self._clock = clock or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------------
    # Login flow
    # ------------------------------------------------------------------

    async def login(
        self,
        *,
        username: str,
        password: str,
        client_ip: str,
        user_agent: str,
        request_id: str | None = None,
    ) -> LocalAdminLoginResult:
        """Verify (username, password) and return a Hub-self-issued JWT.

        Always emits a ``LocalAdminLoginEvent`` (success or failure). On any
        verification problem, raises ``LocalAdminAuthError`` with vague
        detail — callers must not differentiate.
        """
        if self._rate_limit.hit_and_check(f"ip:{client_ip}") is False:
            await self._record_login_event(
                username=username,
                client_ip=client_ip,
                user_agent=user_agent,
                outcome="rate_limited",
                request_id=request_id,
            )
            raise LocalAdminAuthError("authentication failed")
        if self._rate_limit.hit_and_check(f"user:{username}") is False:
            await self._record_login_event(
                username=username,
                client_ip=client_ip,
                user_agent=user_agent,
                outcome="rate_limited",
                request_id=request_id,
            )
            raise LocalAdminAuthError("authentication failed")

        row = await self._fetch_row(username)
        now = self._clock()

        if row is None:
            # Constant-time: still verify against dummy hash so timing leaks
            # nothing about whether the row exists.
            self._verify_password(_DUMMY_PASSWORD, _DUMMY_HASH)  # always fails
            await self._record_login_event(
                username=username,
                client_ip=client_ip,
                user_agent=user_agent,
                outcome="no_such_user",
                request_id=request_id,
            )
            raise LocalAdminAuthError("authentication failed")

        if not row.get("enabled", False):
            self._verify_password(_DUMMY_PASSWORD, _DUMMY_HASH)
            await self._record_login_event(
                username=username,
                client_ip=client_ip,
                user_agent=user_agent,
                outcome="disabled",
                request_id=request_id,
            )
            raise LocalAdminAuthError("authentication failed")

        locked_until_iso = row.get("locked_until")
        if locked_until_iso:
            locked_until = datetime.fromisoformat(locked_until_iso)
            if locked_until > now:
                self._verify_password(_DUMMY_PASSWORD, _DUMMY_HASH)
                await self._record_login_event(
                    username=username,
                    client_ip=client_ip,
                    user_agent=user_agent,
                    outcome="locked_out",
                    request_id=request_id,
                )
                raise LocalAdminAuthError("authentication failed")

        password_ok = self._verify_password(password, row.get("password_hash", ""))
        if not password_ok:
            await self._record_failed_attempt(row, now=now)
            await self._record_login_event(
                username=username,
                client_ip=client_ip,
                user_agent=user_agent,
                outcome="bad_password",
                request_id=request_id,
            )
            raise LocalAdminAuthError("authentication failed")

        # Success — clear failure counters and issue token.
        await self._record_successful_login(row, now=now)
        token = issue_local_admin_token(
            username=username,
            signing_key=self._signing_key,
            ttl_seconds=self._token_ttl,
        )
        await self._record_login_event(
            username=username,
            client_ip=client_ip,
            user_agent=user_agent,
            outcome="success",
            request_id=request_id,
        )
        return LocalAdminLoginResult(
            token=token,
            expires_at=datetime.fromtimestamp(
                time.time() + self._token_ttl, tz=UTC
            ),
            username=username,
        )

    # ------------------------------------------------------------------
    # Auto-disable on first SIAM admin login
    # ------------------------------------------------------------------

    async def disable_on_siam_admin_login(self, *, siam_username: str) -> bool:
        """Idempotent: if a local-admin row exists with ``enabled=true``,
        flip it to ``false`` and emit an audit event. Subsequent calls are
        no-ops. Returns True on the transition, False otherwise."""
        row = await self._fetch_row(_BOOTSTRAP_USERNAME)
        if row is None or not row.get("enabled", False):
            return False
        now = self._clock()
        await self._arcade.command(
            "UPDATE LocalAdmin SET enabled = false, "
            "disabled_at = :ts, disabled_by_siam_username = :who "
            "WHERE username = :u",
            {
                "ts": now.isoformat(),
                "who": siam_username,
                "u": _BOOTSTRAP_USERNAME,
            },
        )
        await self._record_login_event(
            username=_BOOTSTRAP_USERNAME,
            client_ip="-",
            user_agent="-",
            outcome="auto_disabled_on_siam_login",
            request_id=None,
        )
        self._log.info(
            "hub.local_admin.auto_disabled",
            disabled_by_siam_username=siam_username,
        )
        return True

    # ------------------------------------------------------------------
    # Bootstrap: CLI rotates / creates the single LocalAdmin row
    # ------------------------------------------------------------------

    async def bootstrap_set_password(
        self,
        *,
        username: str = _BOOTSTRAP_USERNAME,
        password: str,
    ) -> None:
        """CLI-only: insert or replace the single LocalAdmin row with a fresh
        argon2id-hashed password and ``enabled=true``. Emits a
        ``LocalAdminCredentialRotated`` audit event."""
        password_hash = _HASHER.hash(password)
        now = self._clock()
        existing = await self._fetch_row(username)
        doc = {
            "username": username,
            "password_hash": password_hash,
            "enabled": True,
            "failed_attempts": 0,
            "locked_until": None,
            "last_login_at": None,
            "created_at": existing["created_at"] if existing else now.isoformat(),
            "password_rotated_at": now.isoformat(),
            "disabled_at": None,
            "disabled_by_siam_username": None,
        }
        if existing:
            await self._arcade.command(
                f"UPDATE LocalAdmin CONTENT {json.dumps(doc)} WHERE username = :u",
                {"u": username},
            )
        else:
            await self._arcade.command(
                f"INSERT INTO LocalAdmin CONTENT {json.dumps(doc)}"
            )
        rotation_doc = {
            "id": str(uuid.uuid4()),
            "ts": now.isoformat(),
            "username": username,
            "previous_existed": existing is not None,
        }
        await self._arcade.command(
            f"INSERT INTO LocalAdminCredentialRotated CONTENT {json.dumps(rotation_doc)}"
        )
        self._log.info(
            "hub.local_admin.credential_rotated",
            username=username,
            previous_existed=existing is not None,
        )

    @staticmethod
    def generate_password(*, length: int = 32) -> str:
        """Generate a high-entropy bootstrap password.

        Uses ``secrets.token_urlsafe`` so the output is URL- and shell-safe
        and survives copy-paste through admin tooling without shell quoting.
        """
        return secrets.token_urlsafe(length)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    async def _fetch_row(self, username: str) -> dict[str, Any] | None:
        rows = await self._arcade.query(
            "SELECT FROM LocalAdmin WHERE username = :u",
            {"u": username},
        )
        return rows[0] if rows else None

    def _verify_password(self, password: str, expected_hash: str) -> bool:
        if not expected_hash:
            # No-op verify against dummy still, for timing.
            with contextlib.suppress(VerifyMismatchError, InvalidHashError):
                _HASHER.verify(_DUMMY_HASH, password)
            return False
        try:
            result: bool = _HASHER.verify(expected_hash, password)
        except (VerifyMismatchError, InvalidHashError):
            return False
        return result

    async def _record_failed_attempt(
        self, row: dict[str, Any], *, now: datetime
    ) -> None:
        attempts = int(row.get("failed_attempts", 0)) + 1
        locked_until_iso: str | None = None
        if attempts >= self._failed_threshold:
            locked_until = datetime.fromtimestamp(
                now.timestamp() + self._lockout_duration, tz=UTC
            )
            locked_until_iso = locked_until.isoformat()
        await self._arcade.command(
            "UPDATE LocalAdmin SET failed_attempts = :n, locked_until = :lu "
            "WHERE username = :u",
            {
                "n": attempts,
                "lu": locked_until_iso,
                "u": row["username"],
            },
        )

    async def _record_successful_login(
        self, row: dict[str, Any], *, now: datetime
    ) -> None:
        await self._arcade.command(
            "UPDATE LocalAdmin SET failed_attempts = 0, locked_until = null, "
            "last_login_at = :ts WHERE username = :u",
            {"ts": now.isoformat(), "u": row["username"]},
        )

    async def _record_login_event(
        self,
        *,
        username: str,
        client_ip: str,
        user_agent: str,
        outcome: str,
        request_id: str | None,
    ) -> None:
        doc = {
            "id": str(uuid.uuid4()),
            "ts": self._clock().isoformat(),
            "username": username,
            "client_ip": client_ip,
            "user_agent": user_agent[:512] if user_agent else "-",
            "outcome": outcome,
            "request_id": request_id or str(uuid.uuid4()),
        }
        await self._arcade.command(
            f"INSERT INTO LocalAdminLoginEvent CONTENT {json.dumps(doc)}"
        )
