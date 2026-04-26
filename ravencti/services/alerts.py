"""
services/alerts.py — Alert rule engine.

Rules are data-driven: each rule defines a SQL query and templates
for title/description. Dedup prevents re-alerting within the window.
"""
import logging

from ravencti.config import ALERT_DEDUP_HOURS, MONITORED_COMPANY
from ravencti.db.connection import get_db
from ravencti.utils.helpers import now_str

log = logging.getLogger("ravencti.services.alerts")

_DEDUP = f"datetime('now','-{ALERT_DEDUP_HOURS} hours')"

_RULES = [
    # ── Critical ──────────────────────────────────────────────────────────────
    {
        "q":     "SELECT id,cve_id,product,cvss_score FROM cves WHERE in_cisa_kev=1",
        "t":     "kev_hit",
        "s":     "critical",
        "src":   "cves",
        "title": lambda r: f"ACTIVELY EXPLOITED: {r['cve_id']} in {r['product']}",
        "desc":  lambda r: (f"CISA KEV confirmed active exploitation. "
                            f"CVSS {r['cvss_score']}. Patch immediately."),
    },
    {
        "q":     ("SELECT id,victim_name,ransomware_group,country "
                  "FROM ransomware_incidents WHERE is_client_match=1 AND alert_sent=0"),
        "t":     "ransomware_match",
        "s":     "critical",
        "src":   "ransomware_incidents",
        "title": lambda r: f"CLIENT HIT: {r['victim_name']} targeted by {r['ransomware_group']}",
        "desc":  lambda r: (f"Monitored client in ransomware.live victim post. "
                            f"Group: {r['ransomware_group']}. "
                            f"Country: {r.get('country') or 'Unknown'}."),
    },
    # ── High ──────────────────────────────────────────────────────────────────
    {
        "q":     ("SELECT id,cve_id,product,epss_score,cvss_score FROM cves "
                  "WHERE epss_score>0.5 AND in_cisa_kev=0"),
        "t":     "high_epss",
        "s":     "high",
        "src":   "cves",
        "title": lambda r: f"HIGH EXPLOIT RISK: {r['cve_id']} ({r['epss_score']:.0%} EPSS)",
        "desc":  lambda r: (f"EPSS {r['epss_score']:.1%} — top exploitation tier. "
                            f"Affects {r['product']}. CVSS: {r['cvss_score']}."),
    },
]

_EXPOSURE_RULES = [
    {
        "q":   (f"SELECT id,source,title,severity,url FROM exposure_findings "
                f"WHERE severity IN ('critical','high') AND status='open' "
                f"AND is_relevant=1 AND created_at>={_DEDUP}"),
        "t":   "exposure_critical",
        "s_map": {"critical": "critical", "high": "high"},
        "src": "exposure_findings",
        "title": lambda r: f"EXPOSURE [{r['source'].upper()}]: {r['title'][:120]}",
        "desc":  lambda r: (f"Brand exposure via {r['source']}. "
                            f"Severity: {r['severity']}. URL: {r.get('url') or 'N/A'}"),
    },
    {
        "q":   (f"SELECT id, COUNT(*) as cnt, source FROM exposure_findings "
                f"WHERE status='open' AND is_relevant=1 AND created_at>={_DEDUP} "
                f"GROUP BY source HAVING COUNT(*)>=3"),
        "t":   "exposure_surge",
        "s_map": None,
        "src": "exposure_findings",
        "title": lambda r: f"EXPOSURE SURGE: {r['cnt']} mentions on {r['source']}",
        "desc":  lambda r: (f"{r['cnt']} new {MONITORED_COMPANY} mentions on "
                            f"{r['source']} in {ALERT_DEDUP_HOURS}h."),
    },
]


def run_alerts() -> int:
    """Evaluate all CTI alert rules and insert new alerts. Returns count generated."""
    return _fire_rules(_RULES, is_exposure=False)


def run_exposure_alerts() -> int:
    """Evaluate exposure-specific alert rules."""
    return _fire_rules(_EXPOSURE_RULES, is_exposure=True)


def _fire_rules(rules: list, is_exposure: bool = False) -> int:
    gen = 0
    with get_db() as conn:
        for rule in rules:
            try:
                rows = conn.execute(rule["q"]).fetchall()
                for row in rows:
                    row = dict(row)
                    sev = (
                        rule.get("s_map", {}).get(row.get("severity", "medium"), "medium")
                        if rule.get("s_map") is not None
                        else rule.get("s", "medium")
                    )
                    # Dedup check
                    existing = conn.execute(
                        "SELECT id FROM alerts "
                        "WHERE source_table=? AND source_id=? AND alert_type=? "
                        f"AND created_at>={_DEDUP}",
                        (rule["src"], row["id"], rule["t"]),
                    ).fetchone()
                    if existing:
                        continue
                    conn.execute(
                        "INSERT INTO alerts"
                        "(alert_type,severity,title,description,source_table,source_id)"
                        " VALUES(?,?,?,?,?,?)",
                        (
                            rule["t"], sev,
                            rule["title"](row)[:200],
                            rule["desc"](row)[:500],
                            rule["src"], row["id"],
                        ),
                    )
                    gen += 1

                if not is_exposure and rule["src"] == "ransomware_incidents":
                    conn.execute(
                        "UPDATE ransomware_incidents SET alert_sent=1 WHERE is_client_match=1"
                    )
            except Exception:
                log.exception("Alert rule failed: %s", rule["t"])

    if gen:
        log.info("[ALERTS] Generated %d new alerts", gen)
    return gen
