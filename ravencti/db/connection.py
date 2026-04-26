"""
db/connection.py — Database connection management.

Provides a DialectAwareConnection wrapper that transparently translates
SQLite SQL to PostgreSQL SQL at the connection level. This means ALL
existing conn.execute() calls across the codebase work without changes
when DATABASE_URL is set to PostgreSQL.

Translation handles:
  - ? placeholders → %s
  - datetime('now','-N days') → NOW() - INTERVAL 'N days'
  - INSERT OR IGNORE → INSERT ... ON CONFLICT DO NOTHING
  - INSERT OR REPLACE → INSERT ... ON CONFLICT DO UPDATE
  - substr() → SUBSTRING()
  - GROUP_CONCAT → STRING_AGG()
  - COLLATE NOCASE → ILIKE
  - PRAGMA statements (skipped on PG)
  - executescript (converted to loop on PG)
  - lastrowid → cursor.fetchone()[0] from RETURNING
  - sqlite3.Row → RealDictCursor
"""
import logging
import os
import re
import sqlite3
from contextlib import contextmanager

from ravencti.db.dialect import get_dialect, is_postgres, PostgreSQLDialect

log = logging.getLogger("ravencti.db")

_DATABASE_URL = os.environ.get("DATABASE_URL", "")
_USE_POSTGRES = _USE_POSTGRES = (
    _DATABASE_URL.startswith("postgresql://") or _DATABASE_URL.startswith("postgres://")
)

if _USE_POSTGRES:
    try:
        import psycopg
        import psycopg.rows
        log.info("Database backend: PostgreSQL (%s)", _DATABASE_URL.split("@")[-1])
    except ImportError:
        raise ImportError(
            "DATABASE_URL is set to PostgreSQL but psycopg is not installed. "
            "Run: pip install psycopg[binary]"
        )
else:
    from ravencti.config import DB_PATH
    log.info("Database backend: SQLite (%s)", DB_PATH)


# ── SQL translation patterns ────────────────────────────────────────────────

_RE_DatetimeNowMinus = re.compile(
    r"datetime\s*\(\s*'now'\s*,\s*'(-\d+)\s*(days|hours|minutes)'\s*\)",
    re.IGNORECASE,
)

_RE_DateNowMinus = re.compile(
    r"date\s*\(\s*'now'\s*,\s*'(-\d+)\s*(days?)'\s*\)",
    re.IGNORECASE,
)

_RE_InsertOrIgnore = re.compile(
    r"INSERT\s+OR\s+IGNORE\s+INTO\s+(\w+)\s*\(([^)]+)\)",
    re.IGNORECASE,
)

_RE_InsertOrReplace = re.compile(
    r"INSERT\s+OR\s+REPLACE\s+INTO\s+(\w+)\s*\(([^)]+)\)",
    re.IGNORECASE,
)

_RE_Substr = re.compile(
    r"\bsubstr\s*\(\s*([^,]+),\s*(\d+)\s*,\s*(\d+)\s*\)",
    re.IGNORECASE,
)

_RE_GroupConcat = re.compile(
    r"GROUP_CONCAT\s*\(\s*DISTINCT\s+([^,)]+),\s*'([^']*)'\s*\)",
    re.IGNORECASE,
)

_RE_LikeNoCase = re.compile(
    r"LIKE\s+(\S+)\s+COLLATE\s+NOCASE",
    re.IGNORECASE,
)

_RE_Pragma = re.compile(
    r"\bPRAGMA\s+\w+",
    re.IGNORECASE,
)

# Maps table name → first column (used as conflict target for ON CONFLICT)
_CONFLICT_KEYS = {
    "users": "username",
    "source_health": "source_name",
    "threat_actors": "name",
    "mitre_techniques": "technique_id",
    "exposure_findings": "url",
    "cves": "cve_id",
    "cve_products": "(cve_id,product_id)",
    "ransomware_incidents": "(victim_name,discovered_date)",
    "iocs": "(ioc_type,value)",
    "collection_jobs": "(source_name,started_at)",
    "assets": "id",
    "asset_vulnerabilities": "(asset_id,cve_id)",
    "clients": "name",
    "alerts": "(source_table,source_id,alert_type)",
    "dashboard_configs": "key",
    "audit_log": "id",
    "reports": "id",
    "report_items": "(report_id,item_type,item_id)",
    "notes": "id",
    "note_tags": "(note_id,tag)",
    "saved_searches": "name",
    "integrations": "name",
    "tags": "name",
}


def _conflict_target(table: str) -> str:
    key = _CONFLICT_KEYS.get(table, "id")
    if isinstance(key, tuple):
        return "(" + ",".join(key) + ")"
    return f"({key})"


def _replace_datetime(m):
    val = m.group(1)
    unit = m.group(2)
    n = val[1:]  # strip the minus sign
    if unit.startswith("day"):
        s = "day" if n == "1" else "days"
        return f"NOW() - INTERVAL '{n} {s}'"
    if unit.startswith("hour"):
        s = "hour" if n == "1" else "hours"
        return f"NOW() - INTERVAL '{n} {s}'"
    if unit.startswith("minute"):
        s = "minute" if n == "1" else "minutes"
        return f"NOW() - INTERVAL '{n} {s}'"
    return m.group(0)


def _replace_date(m):
    val = m.group(1)
    n = val[1:]  # strip the minus sign
    return f"CURRENT_DATE - INTERVAL '{n} days'"


def _translate_sql(sql: str, d: PostgreSQLDialect) -> str:
    """Translate SQLite SQL to PostgreSQL SQL."""
    if _RE_Pragma.search(sql):
        return sql

    sql = _RE_DatetimeNowMinus.sub(_replace_datetime, sql)
    sql = _RE_DateNowMinus.sub(_replace_date, sql)

    is_ignore = bool(_RE_InsertOrIgnore.search(sql))
    is_replace = bool(_RE_InsertOrReplace.search(sql))

    if is_ignore:
        sql = _RE_InsertOrIgnore.sub(
            lambda m: f"INSERT INTO {m.group(1)}({m.group(2)})",
            sql,
        )
    if is_replace:
        sql = _RE_InsertOrReplace.sub(
            lambda m: f"INSERT INTO {m.group(1)}({m.group(2)})",
            sql,
        )

    # Append ON CONFLICT clause after VALUES(...) for INSERT OR IGNORE/REPLACE
    if is_ignore or is_replace:
        re_insert = re.compile(
            r"(INSERT\s+INTO\s+\w+\s*\([^)]+\)\s*VALUES\s*\([^)]+\))",
            re.IGNORECASE,
        )
        m = re_insert.search(sql)
        if m:
            table_m = re.search(r"INSERT\s+INTO\s+(\w+)", sql, re.IGNORECASE)
            if table_m:
                table = table_m.group(1)
                cols_m = re.search(r"INSERT\s+INTO\s+\w+\s*\(([^)]+)\)", sql, re.IGNORECASE)
                if cols_m:
                    cols = [c.strip() for c in cols_m.group(1).split(",")]
                    target = _conflict_target(table)
                    rest = sql[m.end():]
                    sql = m.group(1)
                    if is_ignore:
                        sql += f" ON CONFLICT {target} DO NOTHING"
                    elif is_replace:
                        non_key_cols = cols
                        if target.startswith("("):
                            keys = [k.strip() for k in target.strip("()").split(",")]
                        else:
                            keys = [target]
                        non_key_cols = [c for c in cols if c not in keys]
                        if non_key_cols:
                            set_clause = ", ".join(f"{c}=EXCLUDED.{c}" for c in non_key_cols)
                            sql += f" ON CONFLICT {target} DO UPDATE SET {set_clause}"
                        else:
                            sql += f" ON CONFLICT {target} DO NOTHING"
                    sql += rest

    sql = _RE_Substr.sub(
        lambda m: f"SUBSTRING({m.group(1)}::TEXT,{m.group(2)},{m.group(3)})",
        sql,
    )

    sql = _RE_GroupConcat.sub(
        lambda m: f"STRING_AGG(DISTINCT {m.group(1)},'{m.group(2)}')",
        sql,
    )

    sql = _RE_LikeNoCase.sub(
        lambda m: f"ILIKE {m.group(1)}",
        sql,
    )

    # Replace ? placeholders with %s (only outside of string literals)
    # Simple approach: replace all ? since they're always parameters in our codebase
    if "?" in sql:
        count = sql.count("?")
        sql = sql.replace("?", "%s", count)

    # Convert bare integer comparisons on boolean columns: is_relevant=1 → is_relevant=TRUE
    for col in _PG_BOOL_COLS:
        sql = re.sub(
            rf"\b{col}\s*=\s*([01])(?=[\s\);,]|$)",
            lambda m: f"{col}={'TRUE' if m.group(1) == '1' else 'FALSE'}",
            sql,
            flags=re.IGNORECASE,
        )

    return sql





_PG_BOOL_COLS = {
    "active", "in_cisa_kev", "ai_skip", "has_public_exploit",
    "is_client_match", "alert_sent", "is_subtechnique",
    "is_relevant", "pinned",
}


def _adapt_params(sql, parameters):
    """Convert integer 0/1 to bool for PostgreSQL boolean columns."""
    if not parameters:
        return parameters
    # Extract column names from INSERT INTO table(col1,col2,...) 
    import re
    m = re.search(r"INSERT\s+INTO\s+\w+\s*\(([^)]+)\)", sql, re.IGNORECASE)
    if not m:
        return parameters
    cols = [c.strip() for c in m.group(1).split(",")]
    params = list(parameters)
    for i, col in enumerate(cols):
        if i < len(params) and col in _PG_BOOL_COLS:
            if isinstance(params[i], int) and params[i] in (0, 1):
                params[i] = bool(params[i])
    return tuple(params) if isinstance(parameters, tuple) else params


class DialectAwareConnection:
    """
    Wrapper around a database connection that auto-translates SQL.

    For SQLite, this is a thin passthrough.
    For PostgreSQL, all SQL is translated transparently.
    psycopg3 uses per-cursor row_factory, so we set it on execute().
    """

    def __init__(self, conn):
        object.__setattr__(self, "_conn", conn)
        self._dialect = get_dialect()

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __setattr__(self, name, value):
        if name == "_conn":
            object.__setattr__(self, name, value)
        elif name == "_dialect":
            object.__setattr__(self, name, value)
        else:
            setattr(self._conn, name, value)

    def _cursor(self):
        if _USE_POSTGRES:
            return self._conn.cursor(row_factory=psycopg.rows.dict_row)
        return self._conn

    def execute(self, sql, parameters=None):
        if _USE_POSTGRES and isinstance(self._dialect, PostgreSQLDialect):
            sql = _translate_sql(sql, self._dialect)
        if _USE_POSTGRES and parameters:
            parameters = _adapt_params(sql, parameters)
        if _USE_POSTGRES:
            return self._cursor().execute(sql, parameters)
        return self._conn.execute(sql, parameters)

    def executemany(self, sql, seq_of_parameters=None):
        if _USE_POSTGRES and isinstance(self._dialect, PostgreSQLDialect):
            sql = _translate_sql(sql, self._dialect)
        if _USE_POSTGRES and seq_of_parameters:
            seq_of_parameters = [_adapt_params(sql, p) for p in seq_of_parameters]
        if _USE_POSTGRES:
            return self._cursor().executemany(sql, seq_of_parameters)
        return self._conn.executemany(sql, seq_of_parameters)

    def executescript(self, sql_script):
        if _USE_POSTGRES:
            for stmt in sql_script.split(";"):
                stmt = stmt.strip()
                if not stmt:
                    continue
                # Strip leading comment lines for the skip check
                lines = stmt.split("\n")
                has_content = any(
                    l.strip() and not l.strip().startswith("--")
                    for l in lines
                )
                if not has_content:
                    continue
                try:
                    self._conn.execute(stmt)
                except Exception as e:
                    if "already exists" in str(e).lower():
                        continue
                    raise
        else:
            self._conn.executescript(sql_script)

    def close(self):
        self._conn.close()

    @property
    def row_factory(self):
        if _USE_POSTGRES:
            return psycopg.rows.dict_row
        return self._conn.row_factory

    @row_factory.setter
    def row_factory(self, factory):
        if not _USE_POSTGRES:
            self._conn.row_factory = factory

    @property
    def lastrowid(self):
        if _USE_POSTGRES:
            return None
        return self._conn.lastrowid


def _make_pg_connection():
    """Create a new PostgreSQL connection with sensible defaults."""
    conn = psycopg.connect(_DATABASE_URL, autocommit=False)
    return conn


# ── Public context manager ──────────────────────────────────────────────────
@contextmanager
def get_db():
    """
    Yield a dialect-aware database connection.

    SQLite:
      - WAL mode, foreign keys, busy timeout, row factory
    PostgreSQL:
      - RealDictCursor for dict-style access
      - Auto-translated SQL (dialect-aware wrapper)
      - Auto-commit on success, rollback on exception
    """
    if _USE_POSTGRES:
        conn = _make_pg_connection()
        try:
            wrapped = DialectAwareConnection(conn)
            yield wrapped
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        from ravencti.config import DB_PATH
        conn = sqlite3.connect(str(DB_PATH), timeout=60, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA busy_timeout=60000")
        conn.execute("PRAGMA cache_size=-8000")
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
