"""
db/schema.py — Database schema definition, migrations, and seed data.

init_db() is idempotent — safe to call on every startup.
All CREATE TABLE statements use IF NOT EXISTS.
ALTER TABLE migrations are wrapped in try/except (SQLite doesn't support
IF NOT EXISTS on ALTER TABLE).
"""
import json
import logging

from ravencti.db.connection import get_db
from ravencti.utils.helpers import now_str

log = logging.getLogger("ravencti.db.schema")

# ── DDL ────────────────────────────────────────────────────────────────────────
_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    display_name  TEXT DEFAULT '',
    role          TEXT DEFAULT 'analyst',
    active        INTEGER DEFAULT 1,
    last_login    TEXT,
    created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS products (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    product_name  TEXT NOT NULL,
    vendor        TEXT NOT NULL DEFAULT '',
    cpe_prefix    TEXT,
    criticality   TEXT DEFAULT 'medium',
    exposure      TEXT DEFAULT 'external',
    pinned_version TEXT DEFAULT '',
    created_at    TEXT DEFAULT (datetime('now')),
    UNIQUE(product_name, vendor)
);

CREATE TABLE IF NOT EXISTS clients (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    company_name TEXT UNIQUE NOT NULL,
    category     TEXT DEFAULT 'partner',
    criticality  TEXT DEFAULT 'medium',
    sector       TEXT DEFAULT '',
    country_code TEXT DEFAULT '',
    created_at   TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS cves (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id              TEXT UNIQUE NOT NULL,
    product_id          INTEGER REFERENCES products(id),
    product             TEXT,
    vendor              TEXT,
    cvss_score          REAL,
    cvss_vector         TEXT,
    severity            TEXT,
    description         TEXT,
    published_date      TEXT,
    url                 TEXT,
    cwe_ids             TEXT,
    in_cisa_kev         INTEGER DEFAULT 0,
    kev_date_added      TEXT,
    epss_score          REAL,
    epss_percentile     REAL,
    has_public_exploit  INTEGER DEFAULT 0,
    exploit_ids         TEXT,
    attack_techniques   TEXT,
    attack_tactics      TEXT,
    is_product_match    INTEGER DEFAULT 0,
    asset_impact        TEXT,
    risk_score          REAL DEFAULT 0,
    risk_tier           TEXT DEFAULT 'low',
    ai_relevance        REAL DEFAULT -1,
    ai_note             TEXT DEFAULT '',
    ai_skip             INTEGER DEFAULT 0,
    created_at          TEXT DEFAULT (datetime('now')),
    enriched_at         TEXT
);

CREATE TABLE IF NOT EXISTS cve_products (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    cve_id       TEXT NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    product_id   INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    product_name TEXT NOT NULL,
    risk_score   REAL DEFAULT 0,
    risk_tier    TEXT DEFAULT 'low',
    match_method TEXT DEFAULT 'cpe',
    created_at   TEXT DEFAULT (datetime('now')),
    UNIQUE(cve_id, product_id)
);

CREATE TABLE IF NOT EXISTS exploits (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    edb_id        TEXT UNIQUE,
    cve_id        TEXT,
    title         TEXT,
    author        TEXT,
    platform      TEXT,
    exploit_type  TEXT,
    published_date TEXT,
    url           TEXT,
    verified      INTEGER DEFAULT 0,
    source        TEXT DEFAULT 'exploit-db',
    created_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS malware_samples (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    sha256               TEXT UNIQUE NOT NULL,
    md5                  TEXT,
    sha1                 TEXT,
    file_name            TEXT,
    file_type            TEXT,
    file_size            INTEGER,
    malware_family       TEXT DEFAULT '',
    tags                 TEXT,
    first_seen           TEXT,
    source               TEXT DEFAULT 'malwarebazaar',
    related_cve          TEXT,
    enrichment_status    TEXT DEFAULT 'pending',
    enriched_at          TEXT,
    created_at           TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS malware_families (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT UNIQUE NOT NULL,
    description TEXT,
    type        TEXT,
    aliases     TEXT,
    updated_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS iocs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ioc_type       TEXT NOT NULL,
    value          TEXT NOT NULL,
    source         TEXT,
    confidence     INTEGER DEFAULT 50,
    tlp            TEXT DEFAULT 'amber',
    malware_family TEXT DEFAULT '',
    threat_type    TEXT DEFAULT '',
    tags           TEXT,
    related_cve    TEXT,
    country        TEXT,
    first_seen     TEXT DEFAULT (datetime('now')),
    last_seen      TEXT,
    active         INTEGER DEFAULT 1,
    UNIQUE(ioc_type, value)
);

CREATE TABLE IF NOT EXISTS phishing_urls (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    url          TEXT UNIQUE NOT NULL,
    phish_domain TEXT,
    tld          TEXT,
    discovered_at TEXT DEFAULT (datetime('now')),
    active       INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS ransomware_incidents (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    victim_name       TEXT NOT NULL,
    client_id         INTEGER REFERENCES clients(id),
    ransomware_group  TEXT NOT NULL,
    discovered_date   TEXT,
    activity          TEXT,
    country           TEXT,
    data_leaked       INTEGER DEFAULT 0,
    actor_nation      TEXT,
    attack_techniques TEXT,
    alert_level       TEXT DEFAULT 'critical',
    alert_sent        INTEGER DEFAULT 0,
    is_client_match   INTEGER DEFAULT 0,
    match_confidence  REAL DEFAULT 1.0,
    match_method      TEXT DEFAULT 'exact',
    created_at        TEXT DEFAULT (datetime('now')),
    UNIQUE(victim_name, ransomware_group, discovered_date)
);

CREATE TABLE IF NOT EXISTS threat_actors (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    name           TEXT UNIQUE NOT NULL,
    aliases        TEXT,
    nation         TEXT,
    motivation     TEXT,
    target_sectors TEXT,
    ttps           TEXT,
    description    TEXT,
    mitre_id       TEXT,
    source         TEXT DEFAULT 'seeded',
    updated_at     TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS actor_profiles (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_name           TEXT UNIQUE NOT NULL,
    total_victims        INTEGER DEFAULT 0,
    confirmed_clients    INTEGER DEFAULT 0,
    active_since         TEXT,
    last_seen            TEXT,
    top_countries        TEXT,
    top_sectors          TEXT,
    ttps                 TEXT,
    nation               TEXT DEFAULT '',
    motivation           TEXT DEFAULT 'financial',
    description          TEXT DEFAULT '',
    data_leak_rate       REAL DEFAULT 0.0,
    avg_victims_per_month REAL DEFAULT 0.0,
    threat_level         TEXT DEFAULT 'medium',
    mitre_id             TEXT DEFAULT '',
    aliases              TEXT,
    source               TEXT DEFAULT 'derived',
    updated_at           TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    technique_id   TEXT UNIQUE NOT NULL,
    name           TEXT,
    tactic         TEXT,
    description    TEXT,
    detection      TEXT,
    platforms      TEXT,
    is_subtechnique INTEGER DEFAULT 0,
    parent_id      TEXT,
    updated_at     TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type   TEXT NOT NULL,
    severity     TEXT NOT NULL,
    title        TEXT NOT NULL,
    description  TEXT,
    source_table TEXT,
    source_id    INTEGER,
    client_id    INTEGER REFERENCES clients(id),
    status       TEXT DEFAULT 'open',
    created_at   TEXT DEFAULT (datetime('now')),
    resolved_at  TEXT,
    notes        TEXT
);

CREATE TABLE IF NOT EXISTS collection_jobs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type        TEXT NOT NULL,
    status          TEXT DEFAULT 'queued',
    started_at      TEXT,
    completed_at    TEXT,
    items_collected INTEGER DEFAULT 0,
    error_message   TEXT
);

CREATE TABLE IF NOT EXISTS source_health (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    source_name    TEXT UNIQUE NOT NULL,
    last_success   TEXT,
    last_attempt   TEXT,
    status         TEXT DEFAULT 'unknown',
    items_last_run INTEGER DEFAULT 0,
    error_count    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS correlations (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    src_table        TEXT NOT NULL,
    src_id           INTEGER NOT NULL,
    dst_table        TEXT NOT NULL,
    dst_id           INTEGER NOT NULL,
    correlation_type TEXT NOT NULL,
    confidence       REAL DEFAULT 1.0,
    created_at       TEXT DEFAULT (datetime('now')),
    UNIQUE(src_table, src_id, dst_table, dst_id, correlation_type)
);

CREATE TABLE IF NOT EXISTS exposure_findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source          TEXT NOT NULL,
    finding_type    TEXT NOT NULL,
    severity        TEXT DEFAULT 'medium',
    title           TEXT NOT NULL,
    description     TEXT,
    url             TEXT,
    author          TEXT,
    raw_content     TEXT,
    keyword_matched TEXT,
    match_reason    TEXT,
    platform_id     TEXT,
    status          TEXT DEFAULT 'open',
    created_at      TEXT DEFAULT (datetime('now')),
    UNIQUE(source, platform_id)
);
"""

# ── Indexes — every query hot path gets an index ───────────────────────────────
_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_users_username  ON users(username)",
    "CREATE INDEX IF NOT EXISTS idx_cves_risk         ON cves(risk_score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_cves_kev          ON cves(in_cisa_kev)",
    "CREATE INDEX IF NOT EXISTS idx_cves_ai_skip      ON cves(ai_skip, risk_score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_cves_kev_skip     ON cves(in_cisa_kev, ai_skip)",
    "CREATE INDEX IF NOT EXISTS idx_cves_tier         ON cves(risk_tier)",
    "CREATE INDEX IF NOT EXISTS idx_cves_published    ON cves(published_date)",
    "CREATE INDEX IF NOT EXISTS idx_cve_products_cve  ON cve_products(cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_cve_products_prod ON cve_products(product_id)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_status     ON alerts(status, severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_type       ON alerts(alert_type)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_type         ON iocs(ioc_type, value)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_family       ON iocs(malware_family)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_seen         ON iocs(first_seen)",
    "CREATE INDEX IF NOT EXISTS idx_rw_group          ON ransomware_incidents(ransomware_group)",
    "CREATE INDEX IF NOT EXISTS idx_rw_client         ON ransomware_incidents(is_client_match)",
    "CREATE INDEX IF NOT EXISTS idx_rw_date           ON ransomware_incidents(discovered_date)",
    "CREATE INDEX IF NOT EXISTS idx_exposure_source   ON exposure_findings(source, severity)",
    "CREATE INDEX IF NOT EXISTS idx_exposure_status   ON exposure_findings(status, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_malware_family    ON malware_samples(malware_family)",
    "CREATE INDEX IF NOT EXISTS idx_actor_name        ON actor_profiles(actor_name)",
    "CREATE INDEX IF NOT EXISTS idx_jobs_type         ON collection_jobs(job_type, started_at DESC)",
]

# ── Migrations — safe to re-run on every start ────────────────────────────────
# SQLite doesn't support ALTER TABLE … IF NOT EXISTS; catch errors silently.
_MIGRATIONS = [
    ("ALTER TABLE cves ADD COLUMN ai_relevance REAL DEFAULT -1",      "cves.ai_relevance"),
    ("ALTER TABLE cves ADD COLUMN ai_note TEXT DEFAULT ''",            "cves.ai_note"),
    ("ALTER TABLE cves ADD COLUMN ai_skip INTEGER DEFAULT 0",          "cves.ai_skip"),
    ("ALTER TABLE products ADD COLUMN pinned_version TEXT DEFAULT ''", "products.pinned_version"),
    ("ALTER TABLE products ADD COLUMN cpe_prefix TEXT DEFAULT ''",     "products.cpe_prefix"),
    ("ALTER TABLE exposure_findings ADD COLUMN is_relevant INTEGER DEFAULT 0", "exposure_findings.is_relevant"),
    ("ALTER TABLE exposure_findings ADD COLUMN match_reason TEXT DEFAULT ''",     "exposure_findings.match_reason"),
]

# ── Sources to seed ────────────────────────────────────────────────────────────
_SOURCES = [
    "nvd", "cisa_kev", "first_epss", "ransomware_live",
    "mitre_attack",
    "reddit_monitor", "github_monitor", "telegram_monitor", "twitter_monitor",
    "darkforums_monitor", "patched_monitor", "cracked_monitor",
]

_THREAT_ACTORS = [
    ("LockBit",       '["LockBit 2.0","LockBit 3.0"]', "Russia",       "financial",         '["healthcare","finance","manufacturing"]', '["T1486","T1490","T1562","T1027","T1078","T1021"]', "Most prolific RaaS group 2022-2024.",              "G0125"),
    ("BlackCat",      '["ALPHV","Noberus"]',            "Russia",       "financial",         '["healthcare","defense","energy"]',        '["T1486","T1069","T1083","T1021","T1048"]',        "Rust-based RaaS. Critical infrastructure.",        "G0096"),
    ("Clop",          '["TA505","FIN11"]',              "Russia",       "financial",         '["finance","retail","healthcare"]',         '["T1486","T1041","T1190","T1048","T1566"]',        "Mass exploitation of zero-days.",                  "G0154"),
    ("BlackBasta",    '["Black Basta"]',                "Russia",       "financial",         '["manufacturing","healthcare"]',            '["T1486","T1490","T1059","T1078","T1021"]',        "Conti spinoff. Double extortion.",                 "G0135"),
    ("Akira",         '["Akira Ransomware"]',           "Unknown",      "financial",         '["finance","manufacturing","education"]',   '["T1486","T1562","T1190","T1071","T1078"]',        "Targets Cisco VPNs.",                              ""),
    ("RansomHub",     '["RansomHub"]',                  "Unknown",      "financial",         '["healthcare","finance","government"]',     '["T1486","T1490","T1059","T1048","T1041"]',        "Top-tier group post LockBit takedown.",             ""),
    ("Play",          '["PlayCrypt"]',                  "Unknown",      "financial",         '["government","healthcare","finance"]',     '["T1486","T1490","T1562","T1078","T1021"]',        "Targets MSPs.",                                    ""),
    ("Medusa",        '["MedusaLocker"]',               "Unknown",      "financial",         '["education","healthcare","government"]',   '["T1486","T1490","T1059","T1082"]',               "Telegram-based announcements.",                    ""),
    ("Lazarus Group", '["Hidden Cobra","ZINC"]',        "North Korea",  "espionage/financial", '["finance","defense","crypto"]',          '["T1566","T1059","T1027","T1041","T1078"]',        "State-sponsored. Crypto theft.",                   "G0032"),
    ("APT29",         '["Cozy Bear","The Dukes"]',      "Russia",       "espionage",          '["government","defense","healthcare"]',    '["T1566","T1078","T1027","T1021","T1005"]',        "Russian SVR. SolarWinds.",                         "G0016"),
    ("APT41",         '["Double Dragon","Winnti"]',     "China",        "espionage/financial", '["healthcare","telecom","tech"]',         '["T1566","T1190","T1059","T1068","T1027"]',        "Dual espionage + financial.",                       "G0096"),
]

_MITRE_TECHNIQUES = [
    ("T1486", "Data Encrypted for Impact",            "impact",               "Ransomware encryption.",                    "",                           "Windows,Linux,macOS", 0, None),
    ("T1490", "Inhibit System Recovery",               "impact",               "Delete backups, shadow copies.",            "",                           "Windows,Linux,macOS", 0, None),
    ("T1059", "Command and Scripting Interpreter",     "execution",            "Abuse script interpreters.",                "Monitor script execution",   "Windows,Linux,macOS", 0, None),
    ("T1190", "Exploit Public-Facing Application",     "initial-access",       "Exploit internet-facing apps.",             "WAF, patch management",      "Windows,Linux,macOS", 0, None),
    ("T1078", "Valid Accounts",                        "defense-evasion",      "Abuse existing credentials.",               "Monitor logon activity",     "Windows,Linux,macOS,Cloud", 0, None),
    ("T1566", "Phishing",                              "initial-access",       "Send phishing messages.",                   "Email filtering, training",  "Windows,Linux,macOS", 0, None),
    ("T1027", "Obfuscated Files or Information",       "defense-evasion",      "Obfuscate malicious code.",                 "",                           "Windows,Linux,macOS", 0, None),
    ("T1021", "Remote Services",                       "lateral-movement",     "Use valid accounts for remote services.",   "MFA enforcement",            "Windows,Linux,macOS", 0, None),
    ("T1068", "Exploitation for Privilege Escalation","privilege-escalation",  "Exploit software vulnerabilities.",         "Patch management",           "Windows,Linux,macOS", 0, None),
    ("T1005", "Data from Local System",                "collection",           "Search local files.",                       "File access monitoring",     "Windows,Linux,macOS", 0, None),
    ("T1041", "Exfiltration Over C2 Channel",          "exfiltration",         "Exfiltrate via C&C.",                       "Network monitoring",         "Windows,Linux,macOS", 0, None),
    ("T1552", "Unsecured Credentials",                 "credential-access",    "Find unsecured credentials.",               "",                           "Windows,Linux,macOS", 0, None),
]


def init_db() -> None:
    """Create tables, indexes, run migrations, seed reference data."""
    from ravencti.db.connection import is_postgres

    if is_postgres():
        from ravencti.db.schema_pg import init_pg_db
        with get_db() as conn:
            init_pg_db(conn)
            log.info("PostgreSQL schema created / verified")
    else:
        with get_db() as conn:
            conn.executescript(_SCHEMA_SQL)
            log.info("Schema created / verified")

    with get_db() as conn:
        # Migrations
        for sql, label in _MIGRATIONS:
            try:
                conn.execute(sql)
                log.info("Migration applied: %s", label)
            except Exception:
                pass   # column already exists

        # Indexes
        for idx_sql in _INDEXES:
            try:
                conn.execute(idx_sql)
            except Exception:
                pass

    _seed_reference_data()
    _seed_admin_user()
    log.info("Database initialised")


def _seed_admin_user() -> None:
    """Create default admin user if none exists."""
    from ravencti.config import AUTH_ENABLED
    if not AUTH_ENABLED:
        return
    with get_db() as conn:
        existing = conn.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if existing:
            return
        try:
            import bcrypt
            from ravencti.config import DEFAULT_ADMIN_PW
            pw_hash = bcrypt.hashpw(DEFAULT_ADMIN_PW.encode(), bcrypt.gensalt()).decode()
            conn.execute(
                "INSERT OR IGNORE INTO users(username,password_hash,display_name,role,active)"
                " VALUES(?,?,?,?,?)",
                ("admin", pw_hash, "Administrator", "admin", True),
            )
            log.info("Default admin user created (password: '%s')", DEFAULT_ADMIN_PW)
        except ImportError:
            log.warning("bcrypt not installed — admin user not seeded")
        except Exception as e:
            log.warning("Failed to seed admin user: %s", e)


def _seed_reference_data() -> None:
    """Insert static reference rows (idempotent via INSERT OR IGNORE)."""
    with get_db() as conn:
        for s in _SOURCES:
            conn.execute(
                "INSERT OR IGNORE INTO source_health(source_name) VALUES(?)", (s,)
            )
        for actor in _THREAT_ACTORS:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO threat_actors"
                    "(name,aliases,nation,motivation,target_sectors,ttps,description,mitre_id)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    actor,
                )
            except Exception:
                pass
        for tech in _MITRE_TECHNIQUES:
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO mitre_techniques"
                    "(technique_id,name,tactic,description,detection,platforms,is_subtechnique,parent_id)"
                    " VALUES(?,?,?,?,?,?,?,?)",
                    tech,
                )
            except Exception:
                pass


def update_source(name: str, status: str, count: int = 0) -> None:
    """Update source_health row after a collection run."""
    ts = now_str()
    with get_db() as conn:
        if status == "success":
            conn.execute(
                "UPDATE source_health "
                "SET status='active', last_success=?, last_attempt=?, "
                "    items_last_run=?, error_count=0 "
                "WHERE source_name=?",
                (ts, ts, count, name),
            )
        else:
            conn.execute(
                "UPDATE source_health "
                "SET status='error', last_attempt=?, error_count=error_count+1 "
                "WHERE source_name=?",
                (ts, name),
            )
