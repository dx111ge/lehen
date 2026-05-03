"""``python -m lehen_hub.cli`` — operator-facing CLI for Hub bootstrap.

Currently exposes one command: ``create-admin``, which creates or rotates
the single bootstrap admin used by the local-admin path. The generated
password is printed once to stdout; the operator is responsible for
capturing it. Re-running invalidates the previous password.

This is the only path that creates a ``LocalAdmin`` row. The admin UI
does not expose admin user creation — local admin is bootstrap and
break-glass only, and is auto-disabled on the first SIAM admin login.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from typing import NoReturn

import httpx
import structlog

from lehen_hub.admin.local_admin_service import LocalAdminService
from lehen_hub.config import get_settings
from lehen_hub.logging import configure_logging
from lehen_hub.storage.arcade import ArcadeClient
from lehen_hub.storage.bootstrap import ensure_admin_schema


async def _create_admin(username: str) -> str:
    settings = get_settings()
    if (
        not settings.local_admin.enabled
        or settings.local_admin.signing_key is None
    ):
        raise RuntimeError(
            "local-admin path is not configured. Set "
            "LEHEN_LOCAL_ADMIN__ENABLED=true and LEHEN_LOCAL_ADMIN__SIGNING_KEY "
            "(32 url-safe-base64 bytes) before running create-admin."
        )

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(connect=5.0, read=15.0, write=15.0, pool=5.0)
    ) as http:
        arcade = ArcadeClient(settings=settings.arcadedb, http=http)
        # Ensure schema exists so a brand-new Hub can run create-admin
        # before its first start. ``ensure_admin_schema`` is idempotent.
        await ensure_admin_schema(arcade)

        service = LocalAdminService(
            arcade=arcade,
            signing_key=settings.local_admin.get_signing_key_bytes(),
            token_ttl_seconds=settings.local_admin.token_ttl_seconds,
            failed_attempts_threshold=settings.local_admin.failed_attempts_threshold,
            lockout_duration_seconds=settings.local_admin.lockout_duration_seconds,
            rate_limit_per_minute=settings.local_admin.rate_limit_per_minute,
        )
        password = LocalAdminService.generate_password()
        await service.bootstrap_set_password(username=username, password=password)
        return password


def _cmd_create_admin(args: argparse.Namespace) -> NoReturn:
    configure_logging(level="WARNING")  # CLI: keep stderr clean
    log = structlog.get_logger(__name__)
    try:
        password = asyncio.run(_create_admin(username=args.username))
    except Exception as exc:
        log.error("hub.cli.create_admin_failed", error=str(exc))
        print(f"create-admin failed: {exc}", file=sys.stderr)
        sys.exit(1)
    print(
        "Local-admin bootstrap credential created/rotated.\n"
        f"  Username: {args.username}\n"
        f"  Password: {password}\n"
        "\n"
        "Save this password now — it cannot be recovered. Re-running this\n"
        "command invalidates it. The local-admin path auto-disables after\n"
        "the first successful SIAM admin login; re-run to re-enable for an\n"
        "emergency."
    )
    sys.exit(0)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m lehen_hub.cli",
        description="Lehen Hub operator CLI",
    )
    sub = parser.add_subparsers(required=True, dest="command")

    create = sub.add_parser(
        "create-admin",
        help="Create or rotate the bootstrap local admin and print a fresh password.",
    )
    create.add_argument(
        "--username",
        default="admin",
        help="Local admin username (default: admin)",
    )
    create.set_defaults(func=_cmd_create_admin)

    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
