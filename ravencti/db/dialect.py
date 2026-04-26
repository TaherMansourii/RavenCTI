"""
db/dialect.py — SQL dialect abstraction.

Translates between SQLite and PostgreSQL syntax so the rest of the
codebase never has to care which backend is active.

Usage:
    from ravencti.db.dialect import get_dialect
    d = get_dialect()
    d.now()              → "datetime('now')" or "NOW()"
    d.now_minus(days=7) → "datetime('now','-7 days')" or "NOW() - INTERVAL '7 days'"
    d.placeholder      → "?" or "%s"
    d.upsert(table, cols, conflict_cols, pk_return=False)
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod


class Dialect(ABC):

    @abstractmethod
    def placeholder(self) -> str:
        """Return the param placeholder character(s)."""

    @abstractmethod
    def now(self) -> str:
        """Return SQL expression for current timestamp."""

    @abstractmethod
    def now_minus(self, days: int = 0, hours: int = 0, minutes: int = 0) -> str:
        """Return SQL expression for timestamp N units ago."""

    @abstractmethod
    def substr(self, col: str, start: int, length: int) -> str:
        """String substring."""

    @abstractmethod
    def group_concat(self, expr: str, sep: str = ",") -> str:
        """Aggregate strings into a delimited list."""

    @abstractmethod
    def ilike(self, col: str, pattern: str) -> str:
        """Case-insensitive LIKE."""

    @abstractmethod
    def auto_increment(self) -> str:
        """PK auto-generation clause."""

    @abstractmethod
    def ts_default(self) -> str:
        """Default timestamp column type + default."""

    @abstractmethod
    def upsert(self, table: str, columns: list[str],
                conflict_columns: list[str],
                returning: bool = False) -> tuple[str, list[str]]:
        """Return (sql, param_columns) for an INSERT ... ON CONFLICT query."""

    @abstractmethod
    def concat(self, *parts: str) -> str:
        """SQL string concatenation."""

    @abstractmethod
    def add_column_if_missing(self, table: str, column: str,
                              col_type: str, default: str) -> str:
        """Return safe ALTER TABLE ADD COLUMN statement."""

    @abstractmethod
    def true(self) -> str:
        """Return the SQL boolean TRUE literal."""

    @abstractmethod
    def boolean(self) -> str:
        """Return the SQL boolean type name."""

    @abstractmethod
    def json_column_type(self) -> str:
        """Return the JSON/TEXT column type for storing JSON data."""

    @abstractmethod
    def datetime_type(self) -> str:
        """Return the timestamp column type."""

    def param_style(self) -> str:
        return "qmark" if self.placeholder() == "?" else "format"


class SQLiteDialect(Dialect):

    def placeholder(self) -> str:
        return "?"

    def now(self) -> str:
        return "datetime('now')"

    def now_minus(self, days: int = 0, hours: int = 0, minutes: int = 0) -> str:
        parts = []
        if days:
            parts.append(f"'-{days} days'")
        if hours:
            parts.append(f"'-{hours} hours'")
        if minutes:
            parts.append(f"'-{minutes} minutes'")
        if not parts:
            return "datetime('now')"
        args = ",".join(parts)
        return f"datetime('now',{args})"

    def substr(self, col: str, start: int, length: int) -> str:
        return f"substr({col},{start},{length})"

    def group_concat(self, expr: str, sep: str = ",") -> str:
        return f"GROUP_CONCAT(DISTINCT {expr},'{sep}')"

    def ilike(self, col: str, pattern: str) -> str:
        return f"{col} LIKE {pattern} COLLATE NOCASE"

    def auto_increment(self) -> str:
        return "INTEGER PRIMARY KEY AUTOINCREMENT"

    def ts_default(self) -> str:
        return "TEXT DEFAULT (datetime('now'))"

    def upsert(self, table: str, columns: list[str],
                conflict_columns: list[str],
                returning: bool = False) -> tuple[str, list[str]]:
        cols_sql = ", ".join(columns)
        placeholders = ", ".join([self.placeholder()] * len(columns))
        conflict_sql = ", ".join(conflict_columns)
        sql = f"INSERT OR IGNORE INTO {table}({cols_sql}) VALUES({placeholders})"
        return sql, columns

    def concat(self, *parts: str) -> str:
        return " || ".join(parts)

    def add_column_if_missing(self, table: str, column: str,
                              col_type: str, default: str = "") -> str:
        if default:
            return f"ALTER TABLE {table} ADD COLUMN {column} {col_type} DEFAULT {default}"
        return f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"

    def true(self) -> str:
        return "1"

    def boolean(self) -> str:
        return "INTEGER"

    def json_column_type(self) -> str:
        return "TEXT"

    def datetime_type(self) -> str:
        return "TEXT"


class PostgreSQLDialect(Dialect):

    def placeholder(self) -> str:
        return "%s"

    def now(self) -> str:
        return "NOW()"

    def now_minus(self, days: int = 0, hours: int = 0, minutes: int = 0) -> str:
        parts = []
        if days:
            parts.append(f"'{days} days'")
        if hours:
            parts.append(f"'{hours} hours'")
        if minutes:
            parts.append(f"'{minutes} minutes'")
        if not parts:
            return "NOW()"
        interval = " + ".join(parts)
        return f"NOW() - INTERVAL {interval}"

    def substr(self, col: str, start: int, length: int) -> str:
        return f"SUBSTRING({col},{start},{length})"

    def group_concat(self, expr: str, sep: str = ",") -> str:
        return f"STRING_AGG(DISTINCT {expr},'{sep}')"

    def ilike(self, col: str, pattern: str) -> str:
        return f"{col} ILIKE {pattern}"

    def auto_increment(self) -> str:
        return "SERIAL PRIMARY KEY"

    def ts_default(self) -> str:
        return "TIMESTAMPTZ DEFAULT NOW()"

    def upsert(self, table: str, columns: list[str],
                conflict_columns: list[str],
                returning: bool = False) -> tuple[str, list[str]]:
        cols_sql = ", ".join(columns)
        placeholders = ", ".join([self.placeholder()] * len(columns))
        conflict_sql = ", ".join(conflict_columns)
        if returning:
            sql = (
                f"INSERT INTO {table}({cols_sql}) VALUES({placeholders}) "
                f"ON CONFLICT({conflict_sql}) DO NOTHING RETURNING id"
            )
        else:
            sql = (
                f"INSERT INTO {table}({cols_sql}) VALUES({placeholders}) "
                f"ON CONFLICT({conflict_sql}) DO NOTHING"
            )
        return sql, columns

    def concat(self, *parts: str) -> str:
        return " || ".join(parts)

    def add_column_if_missing(self, table: str, column: str,
                              col_type: str, default: str = "") -> str:
        is_pg = isinstance(self, PostgreSQLDialect)
        if_not = "IF NOT EXISTS " if is_pg else ""
        if default:
            return f"ALTER TABLE {table} ADD COLUMN {if_not}{column} {col_type} DEFAULT {default}"
        return f"ALTER TABLE {table} ADD COLUMN {if_not}{column} {col_type}"

    def true(self) -> str:
        return "TRUE"

    def boolean(self) -> str:
        return "BOOLEAN"

    def json_column_type(self) -> str:
        return "JSONB"

    def datetime_type(self) -> str:
        return "TIMESTAMPTZ"


_DATABASE_URL = os.environ.get("DATABASE_URL", "")
_USE_POSTGRES = _DATABASE_URL.startswith("postgresql://") or _DATABASE_URL.startswith("postgres://")

_dialect: Dialect | None = None


def get_dialect() -> Dialect:
    global _dialect
    if _dialect is None:
        _dialect = PostgreSQLDialect() if _USE_POSTGRES else SQLiteDialect()
    return _dialect


def is_postgres() -> bool:
    return _USE_POSTGRES
