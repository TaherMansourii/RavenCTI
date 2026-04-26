"""
collectors/mitre.py — MITRE ATT&CK Enterprise framework loader.

Downloads the enterprise-attack.json bundle and upserts all
attack-pattern objects into mitre_techniques.
"""
import json
import logging

from ravencti.collectors.base import job_start, job_done, update_source
from ravencti.config import MITRE_ATTACK_URLS
from ravencti.db.connection import get_db
from ravencti.utils.helpers import now_str
from ravencti.utils.http import get_session, safe_get

log = logging.getLogger("ravencti.collectors.mitre")


def collect_mitre() -> None:
    jid = job_start("mitre_attack_collection")
    try:
        raw = _fetch_bundle()
        if raw is None:
            update_source("mitre_attack", "error")
            job_done(jid, "failed", 0, "All MITRE ATT&CK URLs failed")
            return

        n = _store_techniques(raw.get("objects", []))
        update_source("mitre_attack", "success", n)
        job_done(jid, "completed", n)
        log.info("[MITRE] Loaded %d techniques", n)

    except Exception as e:
        update_source("mitre_attack", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_mitre failed")


def _fetch_bundle() -> dict | None:
    session = get_session({"User-Agent": "RavenCTI/8.0", "Accept": "application/json"})
    for url in MITRE_ATTACK_URLS:
        r = safe_get(url, session=session, timeout=180)
        if r is None:
            continue
        if r.status_code == 200 and len(r.content) > 10_000:
            log.info("[MITRE] Fetched bundle from %s (%d bytes)", url, len(r.content))
            try:
                return r.json()
            except Exception as e:
                log.warning("[MITRE] JSON parse error from %s: %s", url, e)
        else:
            log.warning("[MITRE] %s → HTTP %d", url, r.status_code)
    return None


def _store_techniques(objects: list) -> int:
    n = 0
    with get_db() as conn:
        for obj in objects:
            if obj.get("type") != "attack-pattern":
                continue
            ext  = obj.get("external_references", [])
            mid  = next((e["external_id"] for e in ext
                         if e.get("source_name") == "mitre-attack"), "")
            if not mid:
                continue
            phases  = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
            tactic  = phases[0] if phases else ""
            is_sub  = 1 if "." in mid else 0
            parent  = mid.split(".")[0] if "." in mid else None
            try:
                conn.execute(
                    "INSERT OR REPLACE INTO mitre_techniques"
                    "(technique_id,name,tactic,description,detection,"
                    " platforms,is_subtechnique,parent_id,updated_at)"
                    " VALUES(?,?,?,?,?,?,?,?,?)",
                    (
                        mid,
                        obj.get("name", ""),
                        tactic,
                        obj.get("description", "")[:500],
                        obj.get("x_mitre_detection", "")[:300],
                        json.dumps(obj.get("x_mitre_platforms", [])),
                        is_sub,
                        parent,
                        now_str(),
                    ),
                )
                n += 1
            except Exception as e:
                log.debug("[MITRE] Insert failed %s: %s", mid, e)
    return n
