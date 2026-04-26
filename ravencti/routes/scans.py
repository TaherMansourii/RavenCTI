"""
routes/scans.py — /api/scan/* endpoints.
"""
from flask import Blueprint, jsonify

from ravencti.db.connection import get_db
from ravencti.routes.auth import require_key
from ravencti.services.queue import enqueue

bp = Blueprint("scans", __name__)


@bp.route("/api/scan/ransomware", methods=["POST"])
@require_key
def scan_ransomware():
    from ravencti.collectors.ransomware import collect_ransomware
    return jsonify({"mode": "ransomware", "jobs": [enqueue(collect_ransomware, "ransomware")]})


@bp.route("/api/scan/cve", methods=["POST"])
@require_key
def scan_cve():
    from ravencti.collectors.cve import collect_cves, collect_kev, collect_epss
    return jsonify({
        "mode": "cve",
        "jobs": [
            enqueue(collect_cves,  "cves"),
            enqueue(collect_kev,   "kev"),
            enqueue(collect_epss,  "epss"),
        ],
    })


@bp.route("/api/scan/exposure", methods=["POST"])
@require_key
def scan_exposure():
    from ravencti.collectors.exposure import (
        collect_reddit_exposure, collect_github_exposure,
        collect_telegram_exposure, collect_paste_exposure,
    )
    return jsonify({
        "mode": "exposure",
        "jobs": [
            enqueue(collect_reddit_exposure,   "reddit"),
            enqueue(collect_github_exposure,   "github"),
            enqueue(collect_telegram_exposure, "telegram"),
            enqueue(collect_paste_exposure,    "paste"),
        ],
    })


@bp.route("/api/scan/status")
@require_key
def scan_status():
    with get_db() as conn:
        rw_total   = conn.execute("SELECT COUNT(*) FROM ransomware_incidents").fetchone()[0]
        rw_clients = conn.execute("SELECT COUNT(*) FROM ransomware_incidents WHERE is_client_match=1").fetchone()[0]
        rw_last    = conn.execute("SELECT MAX(created_at) FROM ransomware_incidents").fetchone()[0]

        cve_total  = conn.execute("SELECT COUNT(*) FROM cves").fetchone()[0]
        cve_kev    = conn.execute("SELECT COUNT(*) FROM cves WHERE in_cisa_kev=1").fetchone()[0]
        cve_crit   = conn.execute("SELECT COUNT(*) FROM cves WHERE risk_tier='critical'").fetchone()[0]
        cve_last   = conn.execute("SELECT MAX(created_at) FROM cves").fetchone()[0]

        ex_open    = conn.execute("SELECT COUNT(*) FROM exposure_findings WHERE status='open'").fetchone()[0]
        ex_crit    = conn.execute("SELECT COUNT(*) FROM exposure_findings WHERE severity IN ('critical','high') AND status='open'").fetchone()[0]
        ex_last    = conn.execute("SELECT MAX(created_at) FROM exposure_findings").fetchone()[0]

        al_open    = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()[0]
        al_crit    = conn.execute("SELECT COUNT(*) FROM alerts WHERE severity='critical' AND status='open'").fetchone()[0]

    return jsonify({
        "ransomware": {"incidents": rw_total, "client_matches": rw_clients, "last_scan": rw_last},
        "cve":        {"total": cve_total, "kev": cve_kev, "critical": cve_crit, "last_scan": cve_last},
        "exposure":   {"open": ex_open, "critical_high": ex_crit, "last_scan": ex_last},
        "alerts":     {"open": al_open, "critical": al_crit},
    })


@bp.route("/api/collect/<source>", methods=["POST"])
@require_key
def collect_source(source: str):
    from ravencti.collectors.cve import collect_cves, collect_kev, collect_epss
    from ravencti.collectors.ransomware import collect_ransomware
    from ravencti.collectors.mitre import collect_mitre
    from ravencti.collectors.cleanup import cleanup_stale_data
    from ravencti.collectors.exposure import (
        collect_reddit_exposure, collect_github_exposure,
        collect_telegram_exposure, collect_paste_exposure,
        collect_crtsh_exposure, collect_dork_exposure, collect_all_exposure,
    )
    from ravencti.collectors.darkweb import collect_all_darkweb
    from ravencti.collectors.darkforums import collect_darkforums
    from ravencti.collectors.patched import collect_patched
    from ravencti.collectors.cracked import collect_cracked
    from ravencti.collectors.twitter import collect_twitter

    dispatch = {
        "cves":       collect_cves,
        "ransomware": collect_ransomware,
        "kev":        collect_kev,
        "epss":       collect_epss,
        "mitre":      collect_mitre,
        "cleanup":    cleanup_stale_data,
        "reddit":     collect_reddit_exposure,
        "github":     collect_github_exposure,
        "telegram":   collect_telegram_exposure,
        "paste":      collect_paste_exposure,
        "crtsh":      collect_crtsh_exposure,
        "dork":       collect_dork_exposure,
        "exposure":   collect_all_exposure,
        "darkweb":    collect_all_darkweb,
        "darkforums": collect_darkforums,
        "patched":    collect_patched,
        "cracked":    collect_cracked,
        "twitter":    collect_twitter,
    }

    if source == "all":
        return jsonify({"jobs": [
            enqueue(collect_cves,        "cves"),
            enqueue(collect_ransomware,  "ransomware"),
            enqueue(collect_all_exposure,"exposure"),
            enqueue(collect_all_darkweb,  "darkweb"),
        ]})

    fn = dispatch.get(source)
    if not fn:
        return jsonify({"error": f"Unknown source: {source}"}), 404
    return jsonify(enqueue(fn, source))