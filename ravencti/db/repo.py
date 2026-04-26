"""
db/repo.py — Repository base class.

Provides a typed, dialect-aware interface for database operations.
Every module that touches SQL should use this (or a subclass) instead
of raw conn.execute() calls.

Design goals:
    - Zero coupling to SQLite or PostgreSQL — the Dialect handles translation
    - Every query uses the dialect's placeholder (? vs %s)
    - Common patterns (find, insert, upsert, count, exists) are one-liners
    - Raw SQL is still accessible via execute() for complex queries
"""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Sequence

from ravencti.db.dialect import Dialect, get_dialect
from ravencti.db.connection import get_db

log = logging.getLogger("ravencti.db.repo")


class BaseRepository:
    """
    Typed repository for a single table.

    Usage:
        repo = BaseRepository("exposure_findings")
        repo.find_all(limit=50)
        repo.find_one(id=5)
        repo.count(source="patched")
        repo.insert(title="...", severity="high")
        repo.update(5, status="resolved")
        repo.upsert({"title": "...", "platform_id": "..."}, ["platform_id"])
    """

    def __init__(self, table: str, dialect: Dialect | None = None):
        self.table = table
        self.d = dialect or get_dialect()

    # ── Context manager (shorthand) ──────────────────────────────────────

    @contextmanager
    def _conn(self):
        with get_db() as c:
            yield c

    # ── Low-level execute ───────────────────────────────────────────────

    def execute(self, sql: str, params: Sequence[Any] | None = None,
               conn=None):
        """Execute raw SQL and return the cursor/rowcount."""
        c = conn or self._conn().__enter__()
        try:
            cursor = c.execute(sql, params or [])
            return cursor
        except Exception:
            if conn is None:
                self._conn().__exit__(None, None, None)
            raise

    def executemany(self, sql: str, params_list: Sequence[Sequence[Any]],
                   conn=None):
        c = conn or self._conn().__enter__()
        try:
            cursor = c.executemany(sql, params_list)
            return cursor
        except Exception:
            if conn is None:
                self._conn().__exit__(None, None, None)
            raise

    # ── SELECT helpers ──────────────────────────────────────────────────

    def find_all(self, where: str = "", params: Sequence[Any] | None = None,
                 order_by: str = "", limit: int = 200, offset: int = 0,
                 columns: str = "*") -> list[dict]:
        sql = f"SELECT {columns} FROM {self.table}"
        if where:
            sql += f" WHERE {where}"
        if order_by:
            sql += f" ORDER BY {order_by}"
        if limit:
            if isinstance(self.d, PostgreSQLDialect):
                sql += f" LIMIT {limit} OFFSET {offset}"
            else:
                sql += f" LIMIT {limit} OFFSET {offset}"
        with self._conn() as conn:
            rows = conn.execute(sql, params or []).fetchall()
            return [dict(r) for r in rows]

    def find_one(self, **kwargs) -> dict | None:
        if not kwargs:
            return None
        where = " AND ".join(f"{k} = {self.d.placeholder()}" for k in kwargs)
        params = list(kwargs.values())
        sql = f"SELECT * FROM {self.table} WHERE {where} LIMIT 1"
        with self._conn() as conn:
            row = conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def find_by_id(self, row_id: int) -> dict | None:
        return self.find_one(id=row_id)

    def count(self, where: str = "", params: Sequence[Any] | None = None) -> int:
        sql = f"SELECT COUNT(*) FROM {self.table}"
        if where:
            sql += f" WHERE {where}"
        with self._conn() as conn:
            return conn.execute(sql, params or []).fetchone()[0]

    def exists(self, **kwargs) -> bool:
        return self.count(
            where=" AND ".join(f"{k} = {self.d.placeholder()}" for k in kwargs),
            params=list(kwargs.values()),
        ) > 0

    # ── INSERT helpers ──────────────────────────────────────────────────

    def insert(self, data: dict[str, Any], returning: bool = False) -> int | None:
        columns = list(data.keys())
        values = list(data.values())
        cols_sql = ", ".join(columns)
        placeholders = ", ".join([self.d.placeholder()] * len(columns))
        suffix = " RETURNING id" if returning and isinstance(self.d, PostgreSQLDialect) else ""
        sql = f"INSERT INTO {self.table}({cols_sql}) VALUES({placeholders}){suffix}"

        with self._conn() as conn:
            cursor = conn.execute(sql, values)
            if returning and isinstance(self.d, PostgreSQLDialect):
                return cursor.fetchone()[0]
            return cursor.lastrowid

    def insert_many(self, rows: list[dict[str, Any]]) -> int:
        if not rows:
            return 0
        columns = list(rows[0].keys())
        cols_sql = ", ".join(columns)
        placeholders = ", ".join([self.d.placeholder()] * len(columns))
        sql = f"INSERT INTO {self.table}({cols_sql}) VALUES({placeholders})"
        params_list = [tuple(r[c] for c in columns) for r in rows]
        with self._conn() as conn:
            conn.executemany(sql, params_list)
            return len(params_list)

    # ── UPSERT ──────────────────────────────────────────────────────────

    def upsert(self, data: dict[str, Any],
               conflict_columns: list[str]) -> int | None:
        """INSERT ... ON CONFLICT DO NOTHING. Returns inserted id or None."""
        sql, _ = self.d.upsert(
            self.table, list(data.keys()), conflict_columns, returning=True
        )
        values = list(data.values())
        with self._conn() as conn:
            cursor = conn.execute(sql, values)
            if isinstance(self.d, PostgreSQLDialect):
                row = cursor.fetchone()
                return row[0] if row else None
            return cursor.lastrowid

    # ── UPDATE ──────────────────────────────────────────────────────────

    def update(self, row_id: int, **kwargs) -> bool:
        if not kwargs:
            return False
        sets = ", ".join(f"{k} = {self.d.placeholder()}" for k in kwargs)
        params = list(kwargs.values()) + [row_id]
        sql = f"UPDATE {self.table} SET {sets} WHERE id = {self.d.placeholder()}"
        with self._conn() as conn:
            cursor = conn.execute(sql, params)
            return cursor.rowcount > 0

    def update_where(self, where: str, params: Sequence[Any],
                     **kwargs) -> int:
        if not kwargs:
            return 0
        sets = ", ".join(f"{k} = {self.d.placeholder()}" for k in kwargs)
        all_params = list(kwargs.values()) + list(params)
        sql = f"UPDATE {self.table} SET {sets} WHERE {where}"
        with self._conn() as conn:
            cursor = conn.execute(sql, all_params)
            return cursor.rowcount

    # ── DELETE ──────────────────────────────────────────────────────────

    def delete(self, row_id: int) -> bool:
        sql = f"DELETE FROM {self.table} WHERE id = {self.d.placeholder()}"
        with self._conn() as conn:
            cursor = conn.execute(sql, [row_id])
            return cursor.rowcount > 0

    def delete_where(self, where: str, params: Sequence[Any] | None = None) -> int:
        sql = f"DELETE FROM {self.table} WHERE {where}"
        with self._conn() as conn:
            cursor = conn.execute(sql, params or [])
            return cursor.rowcount

    def delete_all(self) -> int:
        sql = f"DELETE FROM {self.table}"
        with self._conn() as conn:
            cursor = conn.execute(sql)
            return cursor.rowcount


# Circular import guard for PostgreSQLDialect type check
from ravencti.db.dialect import PostgreSQLDialect  # noqa: E402
