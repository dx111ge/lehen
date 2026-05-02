"""Hub storage: ArcadeDB client + idempotent admin-schema bootstrap.

v1 uses ArcadeDB's HTTP/JSON API for the admin-layer document model. Plan §6.1
mentioned ``asyncpg`` (Postgres wire) — implementation chose HTTP because:

- ArcadeDB's HTTP API is the documented surface for document CRUD.
- ArcadeDB SQL is OrientDB-flavored, which is awkward over asyncpg's prepared
  statement protocol (named params + statement caching are mismatched).
- Postgres-wire is still useful when graph queries land in a later journey;
  the existing ``asyncpg`` dependency stays for that.

Architecture is unchanged: storage is an injectable client behind a clean
async interface. Swapping to asyncpg later is a focused refactor in this
package.
"""

from lehen_hub.storage.arcade import ArcadeClient, ArcadeError, ArcadeQueryError

__all__ = ["ArcadeClient", "ArcadeError", "ArcadeQueryError"]
