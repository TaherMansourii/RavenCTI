"""
db/migrations.py — Schema migration runner.

Migrations are simple Python callables registered with a numeric version.
On startup, `run_pending_migrations()` ensures all migrations have been
applied, tracking state in the `schema_migrations` table.

Each migration receives a `conn` (raw DB-API connection) and the `Dialect`.
It is responsible for its own transactions.

Usage:
    from ravencti.db.migrations import register, run_pending_migrations

    @register(1)
    def add_is_relevant(conn, d):
        conn.execute(d.add_column_if_missing(
            "exposure_findings", "is_relevant", "INTEGER DEFAULT 0"
        ))

    run_pending_migrations()
"""

from __future__ import annotations

import logging
from typing import Callable, Protocol

from ravencti.db.dialect import Dialect, get_dialect
from ravencti.db.connection import get_db

log = logging.getLogger("ravencti.db.migrations")

MigrationFn = Callable[[object, Dialect], None]

_MIGRATIONS: dict[int, MigrationFn] = {}
_MAX_VERSION = 0


class Migration(Protocol):
    def __call__(self, conn: object, d: Dialect) -> None: ...


def register(version: int):
    """Decorator to register a migration function."""
    def decorator(fn: MigrationFn):
        global _MAX_VERSION
        if version in _MIGRATIONS:
            raise ValueError(f"Migration version {version} already registered")
        _MIGRATIONS[version] = fn
        _MAX_VERSION = max(_MAX_VERSION, version)
        return fn
    return decorator


def run_pending_migrations() -> int:
    """Run all unapplied migrations. Returns count of migrations applied."""
    d = get_dialect()

    with get_db() as conn:
        _ensure_tracking_table(conn, d)

        applied = set(
            row[0] for row in conn.execute(
                "SELECT version FROM schema_migrations"
            ).fetchall()
        )

        pending = sorted(v for v in _MIGRATIONS if v not in applied)
        applied_count = 0

        for version in pending:
            fn = _MIGRATIONS[version]
            try:
                log.info("[MIGRATE] Applying migration v%d: %s", version, fn.__name__)
                fn(conn, d)
                conn.execute(
                    "INSERT INTO schema_migrations (version) VALUES (?)",
                    (version,),
                )
                applied_count += 1
                log.info("[MIGRATE] v%d applied successfully", version)
            except Exception:
                log.exception("[MIGRATE] v%d FAILED: %s", version, fn.__name__)
                raise

    if applied_count:
        log.info("[MIGRATE] %d migration(s) applied (versions: %s)",
                 applied_count, pending)
    return applied_count


def _ensure_tracking_table(conn, d: Dialect):
    ddl = f"""
        CREATE TABLE IF NOT EXISTS schema_migrations (
            id         {d.auto_increment()},
            version    INTEGER NOT NULL,
            applied_at {d.ts_default()},
            UNIQUE(version)
        )
    """
    conn.execute(ddl)
