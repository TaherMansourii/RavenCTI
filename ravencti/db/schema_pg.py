"""
db/schema_pg.py -- PostgreSQL-native schema.

This file is used ONLY when DATABASE_URL is set to a PostgreSQL connection.
It defines all 20 tables + 30 indexes using PostgreSQL syntax.

The init_pg_db() function is called from connection.py when PostgreSQL
is detected, replacing the SQLite init_db() path.
"""

from __future__ import annotations

_PG_SCHEMA = """
-- ═══════════════════════════════════════════════════════════════════════
-- CORE: Users & Authentication
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    display_name    TEXT    DEFAULT '',
    role            TEXT    DEFAULT 'analyst'  CHECK (role IN ('admin','analyst')),
    active          BOOLEAN DEFAULT TRUE,
    last_login      TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════════
-- ASSETS: Products & Clients
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS products (
    id              SERIAL PRIMARY KEY,
    product_name    TEXT    NOT NULL,
    vendor          TEXT    DEFAULT '',
    criticality     TEXT    DEFAULT 'medium'   CHECK (criticality IN ('low','medium','high','critical')),
    exposure        TEXT    DEFAULT '',
    cpe_prefix      TEXT    DEFAULT '',
    pinned_version  TEXT    DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (product_name, vendor)
);

CREATE TABLE IF NOT EXISTS clients (
    id              SERIAL PRIMARY KEY,
    company_name    TEXT    NOT NULL UNIQUE,
    domain          TEXT    DEFAULT '',
    category        TEXT    DEFAULT '',
    criticality     TEXT    DEFAULT 'medium',
    sector          TEXT    DEFAULT '',
    notes           TEXT    DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════════
-- CVE Intelligence
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS cves (
    id                  SERIAL PRIMARY KEY,
    cve_id              TEXT    NOT NULL UNIQUE,
    product_id          INTEGER REFERENCES products(id),
    product             TEXT    DEFAULT '',
    vendor              TEXT    DEFAULT '',
    cvss_score          REAL    DEFAULT 0.0,
    cvss_vector         TEXT    DEFAULT '',
    severity            TEXT    DEFAULT '',
    description         TEXT    DEFAULT '',
    published_date      TEXT    DEFAULT '',
    url                 TEXT    DEFAULT '',
    cwe_ids             TEXT    DEFAULT '',
    in_cisa_kev         BOOLEAN DEFAULT FALSE,
    kev_date_added      TEXT    DEFAULT '',
    epss_score          REAL    DEFAULT 0.0,
    epss_percentile     REAL    DEFAULT 0.0,
    has_public_exploit  BOOLEAN DEFAULT FALSE,
    exploit_ids         TEXT    DEFAULT '',
    attack_techniques   TEXT    DEFAULT '',
    attack_tactics      TEXT    DEFAULT '',
    is_product_match    BOOLEAN DEFAULT FALSE,
    asset_impact        TEXT    DEFAULT '',
    risk_score          REAL    DEFAULT 0.0,
    risk_tier           TEXT    DEFAULT '',
    ai_relevance        REAL    DEFAULT -1,
    ai_note             TEXT    DEFAULT '',
    ai_skip             BOOLEAN DEFAULT FALSE,
    created_at          TIMESTAMPTZ DEFAULT NOW(),
    enriched_at         TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS cve_products (
    id              SERIAL PRIMARY KEY,
    cve_id          TEXT    NOT NULL REFERENCES cves(cve_id) ON DELETE CASCADE,
    product_id      INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
    product_name    TEXT    NOT NULL DEFAULT '',
    risk_score      REAL    DEFAULT 0.0,
    risk_tier       TEXT    DEFAULT '',
    match_method    TEXT    DEFAULT 'cpe',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (cve_id, product_id)
);

-- ═══════════════════════════════════════════════════════════════════════
-- Exploits & Malware
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS exploits (
    id              SERIAL PRIMARY KEY,
    edb_id          TEXT    NOT NULL UNIQUE,
    cve_id          TEXT    DEFAULT '',
    name            TEXT    DEFAULT '',
    description     TEXT    DEFAULT '',
    platform        TEXT    DEFAULT '',
    date_added      TEXT    DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS malware_samples (
    id              SERIAL PRIMARY KEY,
    sha256          TEXT    NOT NULL UNIQUE,
    md5             TEXT    DEFAULT '',
    name            TEXT    DEFAULT '',
    file_type       TEXT    DEFAULT '',
    size            INTEGER DEFAULT 0,
    malware_family  TEXT    DEFAULT '',
    tags            TEXT    DEFAULT '',
    source          TEXT    DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS malware_families (
    id              SERIAL PRIMARY KEY,
    name            TEXT    NOT NULL UNIQUE,
    aliases         TEXT    DEFAULT '',
    description     TEXT    DEFAULT '',
    type            TEXT    DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════════
-- IOCs & Phishing
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS iocs (
    id              SERIAL PRIMARY KEY,
    ioc_type        TEXT    NOT NULL,
    value           TEXT    NOT NULL,
    description     TEXT    DEFAULT '',
    malware_family  TEXT    DEFAULT '',
    confidence      TEXT    DEFAULT 'medium',
    source          TEXT    DEFAULT '',
    first_seen      TIMESTAMPTZ DEFAULT NOW(),
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (ioc_type, value)
);

CREATE TABLE IF NOT EXISTS phishing_urls (
    id              SERIAL PRIMARY KEY,
    url             TEXT    NOT NULL UNIQUE,
    title           TEXT    DEFAULT '',
    target          TEXT    DEFAULT '',
    status          TEXT    DEFAULT 'active',
    source          TEXT    DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════════
-- Ransomware Intelligence
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS ransomware_incidents (
    id                SERIAL PRIMARY KEY,
    victim_name       TEXT    NOT NULL,
    client_id         INTEGER REFERENCES clients(id),
    ransomware_group  TEXT    DEFAULT '',
    discovered_date   TEXT    DEFAULT '',
    activity          TEXT    DEFAULT '',
    country           TEXT    DEFAULT '',
    data_leaked       BOOLEAN DEFAULT FALSE,
    actor_nation      TEXT    DEFAULT '',
    attack_techniques TEXT    DEFAULT '',
    alert_level       TEXT    DEFAULT 'critical',
    alert_sent        BOOLEAN DEFAULT FALSE,
    is_client_match   BOOLEAN DEFAULT FALSE,
    match_confidence  REAL    DEFAULT 1.0,
    match_method      TEXT    DEFAULT 'exact',
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (victim_name, ransomware_group, discovered_date)
);

-- ═══════════════════════════════════════════════════════════════════════
-- Threat Actors & MITRE ATT&CK
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS threat_actors (
    id              SERIAL PRIMARY KEY,
    name            TEXT    NOT NULL UNIQUE,
    aliases         JSONB   DEFAULT '[]',
    nation          TEXT    DEFAULT '',
    motivation      TEXT    DEFAULT '',
    target_sectors  JSONB   DEFAULT '[]',
    ttps            JSONB   DEFAULT '[]',
    description     TEXT    DEFAULT '',
    mitre_id        TEXT    DEFAULT '',
    source          TEXT    DEFAULT 'seeded',
    updated_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS actor_profiles (
    id              SERIAL PRIMARY KEY,
    actor_name      TEXT    NOT NULL UNIQUE,
    aliases         JSONB   DEFAULT '[]',
    nation          TEXT    DEFAULT '',
    mitre_id        TEXT    DEFAULT '',
    description     TEXT    DEFAULT '',
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    id                SERIAL PRIMARY KEY,
    technique_id      TEXT    NOT NULL UNIQUE,
    name              TEXT    NOT NULL,
    tactic            TEXT    DEFAULT '',
    description       TEXT    DEFAULT '',
    detection         TEXT    DEFAULT '',
    platforms         TEXT    DEFAULT '',
    is_subtechnique   BOOLEAN DEFAULT FALSE,
    parent_id         TEXT    DEFAULT '',
    updated_at        TIMESTAMPTZ DEFAULT NOW()
);

-- ═══════════════════════════════════════════════════════════════════════
-- Alerts & Jobs
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS alerts (
    id              SERIAL PRIMARY KEY,
    alert_type      TEXT    NOT NULL,
    severity        TEXT    DEFAULT 'medium',
    title           TEXT    DEFAULT '',
    description     TEXT    DEFAULT '',
    source_table    TEXT    DEFAULT '',
    source_id       INTEGER,
    client_id       INTEGER REFERENCES clients(id),
    status          TEXT    DEFAULT 'open',
    notes           TEXT    DEFAULT '',
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS collection_jobs (
    id              SERIAL PRIMARY KEY,
    job_type        TEXT    NOT NULL,
    status          TEXT    DEFAULT 'pending',
    started_at      TIMESTAMPTZ DEFAULT NOW(),
    completed_at    TIMESTAMPTZ,
    items_collected INTEGER DEFAULT 0,
    error_message   TEXT    DEFAULT ''
);

-- ═══════════════════════════════════════════════════════════════════════
-- Operational
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS source_health (
    id              SERIAL PRIMARY KEY,
    source_name     TEXT    NOT NULL UNIQUE,
    last_success    TIMESTAMPTZ,
    last_attempt    TIMESTAMPTZ,
    status          TEXT    DEFAULT 'unknown',
    items_last_run  INTEGER DEFAULT 0,
    error_count     INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS correlations (
    id                SERIAL PRIMARY KEY,
    src_table         TEXT    NOT NULL,
    src_id            INTEGER NOT NULL,
    dst_table         TEXT    NOT NULL,
    dst_id            INTEGER NOT NULL,
    correlation_type  TEXT    DEFAULT '',
    confidence        REAL    DEFAULT 0.0,
    explanation       TEXT    DEFAULT '',
    created_at        TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (src_table, src_id, dst_table, dst_id, correlation_type)
);

-- ═══════════════════════════════════════════════════════════════════════
-- Dark Web / Exposure Intelligence
-- ═══════════════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS exposure_findings (
    id              SERIAL PRIMARY KEY,
    source          TEXT    NOT NULL,
    finding_type    TEXT    NOT NULL,
    severity        TEXT    DEFAULT 'medium',
    title           TEXT    NOT NULL,
    description     TEXT    DEFAULT '',
    url             TEXT    DEFAULT '',
    author          TEXT    DEFAULT '',
    raw_content     TEXT    DEFAULT '',
    keyword_matched TEXT    DEFAULT '',
    match_reason    TEXT    DEFAULT '',
    platform_id     TEXT    NOT NULL,
    is_relevant     BOOLEAN DEFAULT FALSE,
    status          TEXT    DEFAULT 'open',
    created_at      TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE (url)
);
"""

_PG_INDEXES = [
    # Users
    "CREATE UNIQUE INDEX IF NOT EXISTS idx_users_username ON users(username)",

    # CVEs (hot path)
    "CREATE INDEX IF NOT EXISTS idx_cves_risk ON cves(risk_score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_cves_kev ON cves(in_cisa_kev)",
    "CREATE INDEX IF NOT EXISTS idx_cves_ai_skip ON cves(ai_skip, risk_score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_cves_kev_skip ON cves(in_cisa_kev, ai_skip)",
    "CREATE INDEX IF NOT EXISTS idx_cves_tier ON cves(risk_tier)",
    "CREATE INDEX IF NOT EXISTS idx_cves_published ON cves(published_date)",
    "CREATE INDEX IF NOT EXISTS idx_cves_product ON cves(product_id, risk_score DESC)",
    "CREATE INDEX IF NOT EXISTS idx_cves_epss ON cves(epss_score DESC) WHERE epss_score > 0",

    # CVE-Products join
    "CREATE INDEX IF NOT EXISTS idx_cve_products_cve ON cve_products(cve_id)",
    "CREATE INDEX IF NOT EXISTS idx_cve_products_prod ON cve_products(product_id)",

    # Alerts (frequently queried by status)
    "CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status, severity)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type)",
    "CREATE INDEX IF NOT EXISTS idx_alerts_dedup ON alerts(source_table, source_id, alert_type, created_at)",

    # IOCs
    "CREATE INDEX IF NOT EXISTS idx_iocs_type ON iocs(ioc_type, value)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_family ON iocs(malware_family)",
    "CREATE INDEX IF NOT EXISTS idx_iocs_seen ON iocs(first_seen)",

    # Ransomware
    "CREATE INDEX IF NOT EXISTS idx_rw_group ON ransomware_incidents(ransomware_group)",
    "CREATE INDEX IF NOT EXISTS idx_rw_client ON ransomware_incidents(is_client_match)",
    "CREATE INDEX IF NOT EXISTS idx_rw_date ON ransomware_incidents(discovered_date)",
    "CREATE INDEX IF NOT EXISTS idx_rw_matched_date ON ransomware_incidents(is_client_match, discovered_date DESC)",

    # Exposure (relevance-filtered queries are hot)
    "CREATE INDEX IF NOT EXISTS idx_exposure_source ON exposure_findings(source, severity)",
    "CREATE INDEX IF NOT EXISTS idx_exposure_status ON exposure_findings(status, created_at)",
    "CREATE INDEX IF NOT EXISTS idx_exposure_relevant ON exposure_findings(is_relevant, created_at DESC)",

    # Malware
    "CREATE INDEX IF NOT EXISTS idx_malware_family ON malware_samples(malware_family)",

    # Actors
    "CREATE INDEX IF NOT EXISTS idx_actor_name ON actor_profiles(actor_name)",

    # Jobs
    "CREATE INDEX IF NOT EXISTS idx_jobs_type ON collection_jobs(job_type, started_at DESC)",
]


def init_pg_db(conn) -> None:
    """Create all PostgreSQL tables and indexes. Idempotent."""
    conn.executescript(_PG_SCHEMA)
    for idx_sql in _PG_INDEXES:
        try:
            conn.execute(idx_sql)
        except Exception:
            pass
