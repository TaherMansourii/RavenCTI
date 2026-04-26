"""
collectors/ransomware.py — Ransomware victim tracking via ransomware.live.

Sources (tried in order):
  1. api.ransomware.live/v2/recentvictims  (primary)
  2. api.ransomware.live/recentvictims      (v1 fallback)
  3. GitHub ransomwatch mirror              (always-available backup)
"""
import json
import logging
import time

from ravencti.collectors.base import job_start, job_done, update_source
from ravencti.config import RANSOMWARE_URLS
from ravencti.db.connection import get_db
from ravencti.services.matching import match_client, map_rw_ttps
from ravencti.utils.helpers import safe_str, now_str
from ravencti.utils.http import get_session, safe_get

log = logging.getLogger("ravencti.collectors.ransomware")

_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Accept":     "application/json",
}


def collect_ransomware() -> None:
    jid = job_start("ransomware_collection")
    try:
        clients = _get_clients()
        raw     = _fetch_victims()

        if raw is None:
            job_done(jid, "failed", 0, "All ransomware endpoints failed")
            update_source("ransomware_live", "error")
            return

        incidents = _normalise(raw)
        if incidents is None:
            job_done(jid, "failed", 0, f"Unexpected response type: {type(raw)}")
            update_source("ransomware_live", "error")
            return

        log.info("[RW] Processing %d incidents", len(incidents))
        n = _store_incidents(incidents, clients)

        update_source("ransomware_live", "success", n)
        job_done(jid, "completed", n)
        log.info("[RW] Stored %d new incidents", n)

        # Fire alerts after successful ingestion
        from ravencti.services.alerts import run_alerts
        run_alerts()

    except Exception as e:
        update_source("ransomware_live", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_ransomware failed")


def _fetch_victims() -> list | dict | None:
    """Try every endpoint until one returns 200."""
    session = get_session(_HEADERS)
    for url in RANSOMWARE_URLS:
        r = safe_get(url, session=session, timeout=45)
        if r is None:
            continue
        if r.status_code == 200:
            try:
                data = r.json()
                log.info("[RW] %s → %s items", url, len(data) if isinstance(data, list) else type(data).__name__)
                return data
            except Exception as e:
                log.warning("[RW] JSON parse failed for %s: %s", url, e)
                continue
        if r.status_code == 429:
            log.warning("[RW] Rate limited on %s — sleeping 30s", url)
            time.sleep(30)
        else:
            log.warning("[RW] %s → HTTP %d", url, r.status_code)
    return None


def _normalise(raw) -> list | None:
    """Normalise response shape across all sources into a flat list."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return (raw.get("data") or raw.get("posts") or
                raw.get("victims") or raw.get("recentvictims") or [])
    return None


def _store_incidents(incidents: list, clients: list) -> int:
    """Deduplicate and store incidents; return count of new rows."""
    n = 0
    with get_db() as conn:
        for inc in incidents:
            if not isinstance(inc, dict):
                continue

            # Field names differ across sources
            victim = safe_str(
                inc.get("victim") or inc.get("post_title") or
                inc.get("name")   or inc.get("company")
            )
            group  = safe_str(
                inc.get("group")      or inc.get("group_name") or
                inc.get("ransomware") or inc.get("gang")
            )
            if not victim or not group:
                continue

            date    = safe_str(inc.get("attackdate") or inc.get("discovered") or inc.get("date"))
            sector  = safe_str(inc.get("activity")   or inc.get("sector")     or inc.get("industry"))
            country = safe_str(inc.get("country")    or inc.get("nation"))
            leaked  = 1 if (inc.get("data_leaked") or inc.get("leaked")) else 0

            cl, conf, method = match_client(victim, clients) if clients else (None, 0.0, "")
            is_match  = 1 if cl else 0
            client_id = cl.get("id") if cl else None
            ttps      = json.dumps(map_rw_ttps(group))

            try:
                cur = conn.execute(
                    "INSERT OR IGNORE INTO ransomware_incidents"
                    "(victim_name,client_id,ransomware_group,discovered_date,activity,"
                    " country,data_leaked,attack_techniques,is_client_match,alert_level,"
                    " match_confidence,match_method,created_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (victim, client_id, group, date, sector, country, leaked, ttps,
                     is_match, "critical" if is_match else "low",
                     conf, method, now_str()),
                )
                if cur.rowcount > 0:
                    n += 1
            except Exception as e:
                log.debug("[RW] Insert failed: %s", e)

    return n


def _get_clients() -> list[dict]:
    with get_db() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, company_name as name, category, criticality, sector FROM clients"
        ).fetchall()]
