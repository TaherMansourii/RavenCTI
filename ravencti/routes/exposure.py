"""
routes/exposure.py — /api/exposure/* endpoints.
"""
from flask import Blueprint, jsonify, request

from ravencti.config import MONITORED_COMPANY, MONITORED_DOMAIN
from ravencti.db.connection import get_db
from ravencti.routes.auth import require_key
from ravencti.services.queue import enqueue
from ravencti.services.correlation import correlate_findings, classify_incident
from ravencti.services.asset_linking import match_assets_to_incident, load_assets

bp = Blueprint("exposure", __name__)


# =========================
# LIST FINDINGS
# =========================
@bp.route("/api/exposure")
@require_key
def list_exposure():
    source    = request.args.get("source")
    severity  = request.args.get("severity")
    status    = request.args.get("status", "open")
    relevant  = request.args.get("relevant")
    limit     = min(int(request.args.get("limit", 200)), 1000)

    query = "SELECT * FROM exposure_findings WHERE 1=1"
    params = []

    if source:
        query += " AND source=?"
        params.append(source)

    if severity:
        query += " AND severity=?"
        params.append(severity)

    if status != "all":
        query += " AND status=?"
        params.append(status)

    if relevant == "1":
        query += " AND is_relevant=1"
    elif relevant == "0":
        query += " AND is_relevant=0"

    query += (
        " ORDER BY is_relevant DESC, "
        "CASE severity "
        "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
        "WHEN 'medium' THEN 2 ELSE 3 END, created_at DESC LIMIT ?"
    )
    params.append(limit)

    with get_db() as conn:
        rows = conn.execute(query, params).fetchall()

    return jsonify([dict(r) for r in rows])


# =========================
# STATS
# =========================
@bp.route("/api/exposure/stats")
@require_key
def exposure_stats():
    with get_db() as conn:
        total = conn.execute("SELECT COUNT(*) FROM exposure_findings").fetchone()[0]
        open_ct = conn.execute("SELECT COUNT(*) FROM exposure_findings WHERE status='open'").fetchone()[0]
        critical = conn.execute("SELECT COUNT(*) FROM exposure_findings WHERE severity='critical' AND status='open'").fetchone()[0]
        high = conn.execute("SELECT COUNT(*) FROM exposure_findings WHERE severity='high' AND status='open'").fetchone()[0]

        by_src = dict(conn.execute(
            "SELECT source, COUNT(*) FROM exposure_findings WHERE status='open' GROUP BY source"
        ).fetchall())

        by_type = dict(conn.execute(
            "SELECT finding_type, COUNT(*) FROM exposure_findings WHERE status='open' GROUP BY finding_type"
        ).fetchall())

        recent = conn.execute(
            "SELECT COUNT(*) FROM exposure_findings WHERE created_at >= datetime('now','-24 hours')"
        ).fetchone()[0]

        gh_crit = conn.execute(
            "SELECT COUNT(*) FROM exposure_findings WHERE source='github' AND severity IN ('critical','high') AND status='open'"
        ).fetchone()[0]

        relevant_ct = conn.execute(
            "SELECT COUNT(*) FROM exposure_findings WHERE is_relevant=1 AND status='open'"
        ).fetchone()[0]

        dw_total = conn.execute(
            "SELECT COUNT(*) FROM exposure_findings WHERE status='open' AND source IN ('darkforums','patched','cracked')"
        ).fetchone()[0]

        dw_relevant = conn.execute(
            "SELECT COUNT(*) FROM exposure_findings WHERE is_relevant=1 AND status='open' AND source IN ('darkforums','patched','cracked')"
        ).fetchone()[0]

    return jsonify({
        "total": total,
        "open": open_ct,
        "critical": critical,
        "high": high,
        "recent_24h": recent,
        "github_critical": gh_crit,
        "relevant": relevant_ct,
        "darkweb_total": dw_total,
        "darkweb_relevant": dw_relevant,
        "by_source": by_src,
        "by_type": by_type,
        "monitored_company": MONITORED_COMPANY,
        "monitored_domain": MONITORED_DOMAIN,
    })


# =========================
# UPDATE STATUS
# =========================
@bp.route("/api/exposure/<int:eid>", methods=["PATCH"])
@require_key
def update_exposure(eid: int):
    data = request.json or {}
    status = data.get("status")

    if status not in ("open", "reviewed", "false_positive", "resolved"):
        return jsonify({"error": "Invalid status"}), 400

    with get_db() as conn:
        conn.execute(
            "UPDATE exposure_findings SET status=? WHERE id=?",
            (status, eid)
        )

    return jsonify({"success": True})


# =========================
# TRIGGER COLLECTION
# =========================
@bp.route("/api/exposure/collect/<source>", methods=["POST"])
@require_key
def trigger_exposure(source: str):
    from ravencti.collectors.exposure import (
        collect_reddit_exposure,
        collect_github_exposure,
        collect_telegram_exposure,
        collect_paste_exposure,
        collect_crtsh_exposure,
        collect_dork_exposure,
        collect_all_exposure,
    )

    dispatch = {
        "all": collect_all_exposure,
        "reddit": collect_reddit_exposure,
        "github": collect_github_exposure,
        "telegram": collect_telegram_exposure,
        "paste": collect_paste_exposure,
        "crtsh": collect_crtsh_exposure,
        "dork": collect_dork_exposure,
        "twitter": None,
    }

    if source == "twitter":
        from ravencti.collectors.twitter import collect_twitter
        return jsonify(enqueue(collect_twitter, "twitter"))

    fn = dispatch.get(source)

    if not fn:
        return jsonify({"error": f"Unknown source: {source}"}), 404

    return jsonify(enqueue(fn, f"exposure_{source}"))


# =========================
# INCIDENTS (FIXED)
# =========================
@bp.route("/api/exposure/incidents")
@require_key
def incidents():
    try:
        # Load findings
        with get_db() as db:
            rows = db.execute("SELECT * FROM exposure_findings").fetchall()

        findings = [dict(r) for r in rows]

        # Correlate findings → incidents
        incidents = correlate_findings(findings)

        # Load logical assets (clients + products)
        assets = load_assets()

        for inc in incidents:
            # Risk scoring
            inc["risk"] = classify_incident(inc)

            # Asset matching
            matches = match_assets_to_incident(inc, assets)

            inc["affects_company"] = len(matches) > 0
            inc["matched_assets"] = matches

        return jsonify(incidents)

    except Exception as e:
        import traceback
        return jsonify({
            "error": str(e),
            "trace": traceback.format_exc()
        }), 500