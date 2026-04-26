"""
routes/misc.py — alerts, jobs, source health, intelligence summary, reset, debug.
"""
import time as _time

from flask import Blueprint, jsonify, request, send_from_directory

from ravencti.config import BASE_DIR, RANSOMWARE_URLS, NVD_URL, NVD_API_KEY
from ravencti.db.connection import get_db
from ravencti.db.schema import _seed_reference_data
from ravencti.routes.auth import require_key
from ravencti.services.queue import enqueue, queue_depth, drain
from ravencti.utils.helpers import now_str
from ravencti.utils.http import get_session, safe_get

bp = Blueprint("misc", __name__)


# ── Alerts ────────────────────────────────────────────────────────────────────

@bp.route("/api/alerts")
@require_key
def list_alerts():
    status = request.args.get("status", "open")
    with get_db() as conn:
        if status == "all":
            rows = conn.execute(
                "SELECT * FROM alerts ORDER BY severity DESC, created_at DESC LIMIT 500"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM alerts WHERE status=? ORDER BY severity DESC, created_at DESC LIMIT 500",
                (status,),
            ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/api/alerts/<int:aid>", methods=["PATCH"])
@require_key
def update_alert(aid: int):
    d      = request.json or {}
    status = d.get("status")
    if status not in ("open", "acknowledged", "resolved", "false_positive"):
        return jsonify({"error": "Invalid status"}), 400
    with get_db() as conn:
        conn.execute(
            "UPDATE alerts SET status=?, notes=?, resolved_at=? WHERE id=?",
            (status, d.get("notes"),
             now_str() if status == "resolved" else None, aid),
        )
    return jsonify({"success": True})


@bp.route("/api/alerts/stats")
@require_key
def alert_stats():
    with get_db() as conn:
        total   = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
        open_ct = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        crit    = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical' AND status='open'").fetchone()[0]
        by_type = dict(conn.execute("SELECT alert_type,COUNT(*) FROM alerts GROUP BY alert_type").fetchall())
    return jsonify({"total": total, "open": open_ct, "critical_open": crit, "by_type": by_type})


# ── Jobs & source health ──────────────────────────────────────────────────────

@bp.route("/api/jobs")
@require_key
def list_jobs():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM collection_jobs ORDER BY id DESC LIMIT 100"
        ).fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/api/sources/health")
@require_key
def source_health():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM source_health ORDER BY source_name").fetchall()
    return jsonify([dict(r) for r in rows])


# ── Intelligence summary & timeline ───────────────────────────────────────────

@bp.route("/api/intelligence/summary")
@require_key
def intelligence_summary():
    with get_db() as conn:
        return jsonify({
            "cves": {
                "total":       conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0],
                "critical":    conn.execute("SELECT COUNT(*) FROM cves WHERE risk_tier='critical'").fetchone()[0],
                "kev":         conn.execute("SELECT COUNT(*) FROM cves WHERE in_cisa_kev=1").fetchone()[0],
                "high_epss":   conn.execute("SELECT COUNT(*) FROM cves WHERE epss_score>0.5").fetchone()[0],
            },
            "ransomware": {
                "total":         conn.execute("SELECT COUNT(*) FROM ransomware_incidents").fetchone()[0],
                "client_matches":conn.execute("SELECT COUNT(*) FROM ransomware_incidents WHERE is_client_match=1").fetchone()[0],
                "groups":        conn.execute("SELECT COUNT(DISTINCT ransomware_group) FROM ransomware_incidents").fetchone()[0],
            },
            "alerts": {
                "open":     conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0],
                "critical": conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical' AND status='open'").fetchone()[0],
            },
            "exposure": {
                "relevant":    conn.execute("SELECT COUNT(*) FROM exposure_findings WHERE status='open' AND is_relevant=1").fetchone()[0],
                "open":        conn.execute("SELECT COUNT(*) FROM exposure_findings WHERE status='open'").fetchone()[0],
                "recent_24h":  conn.execute("SELECT COUNT(*) FROM exposure_findings WHERE created_at>=datetime('now','-24 hours') AND is_relevant=1").fetchone()[0],
            },
            "iocs": {
                "total":      conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0],
                "recent_24h": conn.execute("SELECT COUNT(*) FROM iocs WHERE first_seen>=datetime('now','-24 hours')").fetchone()[0],
            },
        })


@bp.route("/api/intelligence/timeline")
@require_key
def intelligence_timeline():
    with get_db() as conn:
        return jsonify({
            "cve_timeline": [dict(r) for r in conn.execute(
                "SELECT substr(created_at,1,10) as day, COUNT(*) as count "
                "FROM cves WHERE created_at>=date('now','-30 days') "
                "GROUP BY day ORDER BY day"
            ).fetchall()],
            "rw_timeline": [dict(r) for r in conn.execute(
                "SELECT substr(created_at,1,10) as day, COUNT(*) as count "
                "FROM ransomware_incidents WHERE created_at>=date('now','-30 days') "
                "GROUP BY day ORDER BY day"
            ).fetchall()],
        })


# ── Reset ─────────────────────────────────────────────────────────────────────

@bp.route("/api/reset", methods=["POST"])
@require_key
def reset_intel():
    """
    Wipe all collected intelligence. Preserves products and clients.
    Uses executescript (auto-commits per statement) to avoid WAL lock contention.
    Drains the job queue first so no collector holds a write lock.
    """
    tables = [
        "cves", "cve_products", "malware_samples", "malware_families",
        "iocs", "phishing_urls", "ransomware_incidents", "threat_actors",
        "actor_profiles", "mitre_techniques", "alerts", "collection_jobs",
        "source_health", "correlations", "exposure_findings",
    ]
    try:
        drain(timeout=30)

        with get_db() as conn:
            for t in tables:
                try:
                    conn.execute(f"DELETE FROM {t}")
                except Exception:
                    pass

        _seed_reference_data()
        return jsonify({
            "success":   True,
            "preserved": ["products", "clients"],
            "message":   "All intelligence reset. Run a scan to repopulate.",
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── Debug & test ─────────────────────────────────────────────────────────────

@bp.route("/api/debug/scan")
@require_key
def debug_scan():
    out: dict = {"checks": [], "ok": True}

    def chk(name: str, passed: bool, detail: str = "") -> None:
        out["checks"].append({"check": name, "passed": passed, "detail": str(detail)})
        if not passed:
            out["ok"] = False

    with get_db() as conn:
        prods   = conn.execute("SELECT id,product_name,vendor FROM products").fetchall()
        clients = conn.execute("SELECT COUNT(*) FROM clients").fetchone()[0]
        cves    = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        rw      = conn.execute("SELECT COUNT(*) FROM ransomware_incidents").fetchone()[0]
        jobs    = conn.execute(
            "SELECT job_type,status,items_collected,error_message,started_at "
            "FROM collection_jobs ORDER BY id DESC LIMIT 10"
        ).fetchall()

    chk("Products configured", len(prods) > 0,
        f"{len(prods)}: " + ", ".join(p["product_name"] for p in prods[:5]))
    chk("Clients configured",  clients > 0,  f"{clients} clients")
    chk("CVEs in DB",          cves > 0,     f"{cves} CVEs")
    chk("Ransomware in DB",    rw > 0,       f"{rw} incidents")

    # NVD connectivity
    hdrs = {"User-Agent": "RavenCTI/8.0"}
    if NVD_API_KEY:
        hdrs["apiKey"] = NVD_API_KEY
    session = get_session(hdrs)
    r = safe_get(NVD_URL, session=session,
                 params={"cveId": "CVE-2024-21762"}, timeout=15)
    if r and r.status_code == 200:
        total = r.json().get("totalResults", 0)
        chk("NVD API reachable", True, f"HTTP 200, {total} results for CVE-2024-21762")
    else:
        chk("NVD API reachable", False,
            f"HTTP {r.status_code if r else 'no response'}")

    # Ransomware.live connectivity
    rw_session = get_session({"User-Agent": "Mozilla/5.0", "Accept": "application/json"})
    rw_ok = False
    for url in RANSOMWARE_URLS:
        r2 = safe_get(url, session=rw_session, timeout=15)
        if r2 and r2.status_code == 200:
            chk("Ransomware.live reachable", True, url)
            rw_ok = True
            break
    if not rw_ok:
        chk("Ransomware.live reachable", False, "All endpoints failed")

    out["recent_jobs"] = [
        {"type": j["job_type"], "status": j["status"],
         "items": j["items_collected"], "error": j["error_message"],
         "started": j["started_at"]}
        for j in jobs
    ]
    out["queue_depth"] = queue_depth()
    return jsonify(out)


@bp.route("/api/test")
def api_test():
    return jsonify({
        "status":  "ok",
        "version": "v8.0",
        "queue":   queue_depth(),
    })


@bp.route("/")
def serve_dashboard():
    import os, time
    filepath = os.path.join(str(BASE_DIR), "dashboard.html")
    resp = send_from_directory(str(BASE_DIR), "dashboard.html")
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    return resp
