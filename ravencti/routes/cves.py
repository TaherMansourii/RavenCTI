"""
routes/cves.py — /api/cves and /api/cves/stats
"""
from flask import Blueprint, jsonify, request

from ravencti.db.connection import get_db
from ravencti.routes.auth import require_key
from ravencti.utils.helpers import json_or

bp = Blueprint("cves", __name__)


@bp.route("/api/cves")
@require_key
def list_cves():
    tier       = request.args.get("tier")
    kev        = request.args.get("kev")
    show_skip  = request.args.get("show_skipped", "0") == "1"
    limit      = min(int(request.args.get("limit", 500)), 2000)

    q = (
        "SELECT c.*, GROUP_CONCAT(DISTINCT cp.product_name) as all_products "
        "FROM cves c LEFT JOIN cve_products cp ON c.cve_id=cp.cve_id WHERE 1=1"
    )
    p = []
    if not show_skip:
        q += " AND c.ai_skip=0"
    if tier:
        q += " AND c.risk_tier=?"; p.append(tier)
    if kev == "1":
        q += " AND c.in_cisa_kev=1"
    q += " GROUP BY c.id ORDER BY c.risk_score DESC, c.cvss_score DESC LIMIT ?"
    p.append(limit)

    with get_db() as conn:
        rows = conn.execute(q, p).fetchall()

    return jsonify([{
        "id":               r["id"],
        "cve_id":           r["cve_id"],
        "product":          r["product"],
        "vendor":           r["vendor"],
        "all_products":     list(set((r["all_products"] or r["product"] or "").split(","))),
        "cvss_score":       r["cvss_score"],
        "cvss_vector":      r["cvss_vector"],
        "severity":         r["severity"],
        "description":      r["description"],
        "published_date":   r["published_date"],
        "url":              r["url"],
        "cwe_ids":          json_or(r["cwe_ids"], []),
        "in_cisa_kev":      bool(r["in_cisa_kev"]),
        "kev_date_added":   r["kev_date_added"],
        "epss_score":       r["epss_score"],
        "epss_percentile":  r["epss_percentile"],
        "has_public_exploit": bool(r["has_public_exploit"]),
        "attack_techniques":  json_or(r["attack_techniques"], []),
        "attack_tactics":     json_or(r["attack_tactics"], []),
        "risk_score":       r["risk_score"],
        "risk_tier":        r["risk_tier"],
        "ai_relevance":     r["ai_relevance"],
        "ai_note":          r["ai_note"],
        "ai_skip":          bool(r["ai_skip"]),
        "created_at":       r["created_at"],
        "enriched_at":      r["enriched_at"],
    } for r in rows])


@bp.route("/api/cves/stats")
@require_key
def cve_stats():
    with get_db() as conn:
        base    = "WHERE ai_skip=0"
        total   = conn.execute(f"SELECT COUNT(*) FROM cves {base}").fetchone()[0]
        crit    = conn.execute(f"SELECT COUNT(*) FROM cves {base} AND risk_tier='critical'").fetchone()[0]
        high    = conn.execute(f"SELECT COUNT(*) FROM cves {base} AND risk_tier='high'").fetchone()[0]
        med     = conn.execute(f"SELECT COUNT(*) FROM cves {base} AND risk_tier='medium'").fetchone()[0]
        kev     = conn.execute(f"SELECT COUNT(*) FROM cves WHERE in_cisa_kev=1 AND ai_skip=0").fetchone()[0]
        hi_epss = conn.execute(f"SELECT COUNT(*) FROM cves {base} AND epss_score>0.5").fetchone()[0]
        skipped = conn.execute("SELECT COUNT(*) FROM cves WHERE ai_skip=1").fetchone()[0]
        by_prod = dict(conn.execute(
            "SELECT cp.product_name, COUNT(DISTINCT cp.cve_id) "
            "FROM cve_products cp JOIN cves c ON cp.cve_id=c.cve_id "
            "WHERE c.ai_skip=0 GROUP BY cp.product_name "
            "ORDER BY COUNT(*) DESC LIMIT 10"
        ).fetchall()) or dict(conn.execute(
            "SELECT product, COUNT(*) FROM cves WHERE ai_skip=0 "
            "GROUP BY product ORDER BY COUNT(*) DESC LIMIT 10"
        ).fetchall())
        ed = conn.execute(
            f"SELECT "
            f"SUM(CASE WHEN epss_score< 0.01 THEN 1 ELSE 0 END),"
            f"SUM(CASE WHEN epss_score>=0.01 AND epss_score<0.1  THEN 1 ELSE 0 END),"
            f"SUM(CASE WHEN epss_score>=0.1  AND epss_score<0.5  THEN 1 ELSE 0 END),"
            f"SUM(CASE WHEN epss_score>=0.5  THEN 1 ELSE 0 END) "
            f"FROM cves {base}"
        ).fetchone()

    return jsonify({
        "total": total, "critical": crit, "high": high, "medium": med,
        "low": max(total - crit - high - med, 0),
        "kev_count": kev, "high_epss": hi_epss, "ai_skipped": skipped,
        "by_product": by_prod,
        "epss_distribution": {
            "<1%": ed[0] or 0, "1-10%": ed[1] or 0,
            "10-50%": ed[2] or 0, ">50%": ed[3] or 0,
        },
    })


@bp.route("/api/cves/deduplicate", methods=["POST"])
@require_key
def deduplicate_cves():
    """Remove keyword false-positives and sub-threshold CVEs."""
    body      = request.json or {}
    dry_run   = body.get("dry_run", False)
    min_cvss  = float(body.get("min_cvss", 6.0))

    removed_cvss = removed_norel = kept = 0

    with get_db() as conn:
        all_cves  = conn.execute(
            "SELECT id, cve_id, cvss_score, description, product FROM cves"
        ).fetchall()
        to_delete = []

        for row in all_cves:
            cvss  = row["cvss_score"] or 0
            desc  = (row["description"] or "").lower()
            prod  = (row["product"]     or "").lower().replace("_", " ").replace("-", " ")

            if 0 < cvss < min_cvss:
                to_delete.append(row["id"])
                removed_cvss += 1
                continue

            if desc and prod:
                tokens = [t for t in prod.split() if len(t) > 3]
                if prod not in desc and not any(t in desc for t in tokens):
                    to_delete.append(row["id"])
                    removed_norel += 1
                    continue

            kept += 1

        if not dry_run and to_delete:
            for i in range(0, len(to_delete), 500):
                batch = to_delete[i:i+500]
                conn.execute(
                    f"DELETE FROM cves WHERE id IN ({','.join('?'*len(batch))})", batch
                )
            conn.execute(
                "DELETE FROM alerts WHERE source_table='cves' "
                "AND source_id NOT IN (SELECT id FROM cves)"
            )

    return jsonify({
        "dry_run":          dry_run,
        "removed_low_cvss": removed_cvss,
        "removed_irrelevant": removed_norel,
        "kept":             kept,
        "total_removed":    len(to_delete) if not dry_run else 0,
    })
