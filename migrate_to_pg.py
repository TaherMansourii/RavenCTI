"""
migrate_to_pg.py — Export all data from SQLite and import into PostgreSQL.

Usage:
    export DATABASE_URL=postgresql://user:pass@host:5432/ravencti
    python migrate_to_pg.py

Prerequisites:
    pip install psycopg[binary]
"""
import os
import sys
import sqlite3
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")
log = logging.getLogger("migrate")


def main():
    database_url = os.environ.get("DATABASE_URL", "")
    if not database_url or not database_url.startswith("postgresql"):
        print("ERROR: Set DATABASE_URL to a PostgreSQL connection string.")
        print("  export DATABASE_URL=postgresql://user:pass@localhost:5432/ravencti")
        sys.exit(1)

    try:
        import psycopg
    except ImportError:
        print("ERROR: psycopg not installed. Run: pip install psycopg[binary]")
        sys.exit(1)

    from ravencti.config import DB_PATH

    sqlite_conn = sqlite3.connect(str(DB_PATH))
    sqlite_conn.row_factory = sqlite3.Row

    pg_conn = psycopg.connect(database_url, autocommit=False)

    try:
        _migrate(sqlite_conn, pg_conn)
    finally:
        pg_conn.close()
        sqlite_conn.close()


def _migrate(sqlite_conn, pg_conn):
    cur = pg_conn.cursor()

    log.info("Creating PostgreSQL schema...")
    from ravencti.db.schema_pg import _PG_SCHEMA as pg_schema
    for statement in pg_schema.split(";"):
        statement = statement.strip()
        if statement:
            try:
                cur.execute(statement)
            except psycopg.errors.DuplicateTable:
                pass
    pg_conn.commit()
    log.info("Schema created.")

    sqlite_cur = sqlite_conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    tables = [row["name"] for row in sqlite_cur.fetchall()]

    skip_tables = {"schema_migrations"}
    tables = [t for t in tables if t not in skip_tables]

    # Migrate in dependency order to satisfy foreign keys
    _order = [
        "users", "products", "clients",  # no deps
        "cves", "cve_products",          # cve_products depends on cves, products
        "exploits", "malware_families", "malware_samples",
        "iocs", "phishing_urls",
        "ransomware_incidents",          # depends on clients
        "threat_actors", "actor_profiles", "mitre_techniques",
        "alerts", "collection_jobs", "source_health",
        "correlations", "exposure_findings",
    ]
    ordered = [t for t in _order if t in tables]
    remaining = [t for t in tables if t not in ordered]
    tables = ordered + remaining

    log.info("Found %d tables to migrate.", len(tables))

    for table in tables:
        try:
            _migrate_table(sqlite_conn, pg_conn, cur, table)
        except Exception as e:
            log.error("FAILED to migrate table %s: %s", table, e)
            pg_conn.rollback()
            raise

    pg_conn.commit()

    _verify(sqlite_conn, pg_conn, tables)

    log.info("Running seed (reference data, threat actors, MITRE)...")
    from ravencti.db.schema import _seed_reference_data
    _seed_reference_data()
    log.info("Seed complete.")

    log.info("Migration complete!")


_MIGRATE_BOOL_COLS = {
    "cves": {"in_cisa_kev", "has_public_exploit", "is_product_match", "ai_skip"},
    "cve_products": set(),
    "ransomware_incidents": {"data_leaked", "alert_sent", "is_client_match"},
    "mitre_techniques": {"is_subtechnique"},
    "exposure_findings": {"is_relevant"},
    "alerts": {"alert_sent"},
    "users": {"active"},
}


def _migrate_table(sqlite_conn, pg_conn, pg_cur, table):
    count = sqlite_conn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]
    if count == 0:
        log.info("  %s: 0 rows, skipping.", table)
        return

    row = sqlite_conn.execute(f"SELECT * FROM [{table}] LIMIT 1").fetchone()
    if row is None:
        log.info("  %s: empty table, skipping.", table)
        return
    columns = list(row.keys())
    col_list = ", ".join(columns)
    placeholders = ", ".join(f"%({c})s" for c in columns)

    rows = sqlite_conn.execute(f"SELECT * FROM [{table}]").fetchall()

    log.info("  %s: %d rows...", table, len(rows))

    batch_size = 500
    for i in range(0, len(rows), batch_size):
        batch = rows[i:i + batch_size]
        dicts = [dict(r) for r in batch]
        for d in dicts:
            for k, v in d.items():
                if v is None:
                    continue
                if isinstance(v, int) and v in (0, 1):
                    if k in (
                        "active", "in_cisa_kev", "ai_skip", "has_public_exploit",
                        "is_product_match", "is_client_match", "alert_sent",
                        "is_subtechnique", "is_relevant", "pinned",
                        "data_leaked",
                    ):
                        d[k] = bool(v)

        try:
            rows_tuples = [tuple(d[c] for c in columns) for d in dicts]
            sql = f"INSERT INTO {table} ({col_list}) VALUES ({', '.join(['%s']*len(columns))}) ON CONFLICT DO NOTHING"
            pg_cur.executemany(sql, rows_tuples)
            pg_conn.commit()
        except Exception as e:
            log.warning("  Batch failed for %s, trying row-by-row: %s", table, e)
            pg_conn.rollback()
            for d in dicts:
                try:
                    pg_cur.execute(
                        f"INSERT INTO {table} ({col_list}) VALUES ({placeholders}) "
                        f"ON CONFLICT DO NOTHING",
                        d,
                    )
                except Exception as row_err:
                    log.debug("  Row failed: %s", row_err)
            pg_conn.commit()

    log.info("  %s: done.", table)


def _verify(sqlite_conn, pg_conn, tables):
    log.info("Verifying row counts...")
    pg_cur = pg_conn.cursor()
    all_ok = True
    for table in tables:
        sl_count = sqlite_conn.execute(f"SELECT COUNT(*) FROM [{table}]").fetchone()[0]
        pg_cur.execute(f"SELECT COUNT(*) FROM {table}")
        pg_count = pg_cur.fetchone()[0]
        status = "OK" if sl_count == pg_count else "MISMATCH"
        if status != "OK":
            all_ok = False
        log.info("  %s: SQLite=%d PostgreSQL=%d [%s]", table, sl_count, pg_count, status)

    if all_ok:
        log.info("All row counts match!")
    else:
        log.warning("Some row counts differ.")


if __name__ == "__main__":
    main()
