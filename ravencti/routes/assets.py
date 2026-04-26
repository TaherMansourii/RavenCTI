
"""
routes/assets.py — /api/products, /api/clients, /api/iocs, /api/ransomware,
                   /api/threat-actors, /api/mitre/techniques
"""
import json
import sqlite3

try:
    from psycopg.errors import UniqueViolation as PgUniqueViolation
except ImportError:
    PgUniqueViolation = type(None)

from flask import Blueprint, jsonify, request

from ravencti.db.connection import get_db
from ravencti.routes.auth import require_key
from ravencti.utils.helpers import json_or

bp = Blueprint("assets", __name__)


# ── Products ───────────────────────────────────────────────────────────────────

@bp.route("/api/products", methods=["GET"])
@require_key
def get_products():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM products ORDER BY product_name").fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/api/products", methods=["POST"])
@require_key
def add_product():
    d    = request.json or {}
    name = d.get("product_name", "").strip().lower()
    if not name:
        return jsonify({"error": "product_name required"}), 400
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO products(product_name,vendor,criticality,exposure,pinned_version,cpe_prefix)"
                " VALUES(?,?,?,?,?,?)",
                (name, d.get("vendor", "").strip().lower(),
                 d.get("criticality",  "medium"),
                 d.get("exposure",     "external"),
                 d.get("pinned_version", ""),
                 d.get("cpe_prefix",   "").strip()),  # e.g. "cpe:2.3:a:nginx:nginx"
            )
        return jsonify({"success": True})
    except (sqlite3.IntegrityError, PgUniqueViolation):
        return jsonify({"error": "Product already exists"}), 409
@bp.route("/api/products/<int:pid>", methods=["DELETE"])
@require_key
def del_product(pid: int):
    with get_db() as conn:
        conn.execute("DELETE FROM products WHERE id=?", (pid,))
    return jsonify({"success": True})


# ── Clients ────────────────────────────────────────────────────────────────────

@bp.route("/api/clients", methods=["GET"])
@require_key
def get_clients():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM clients ORDER BY company_name").fetchall()
    return jsonify([dict(r) for r in rows])


@bp.route("/api/clients", methods=["POST"])
@require_key
def add_client():
    d    = request.json or {}
    name = d.get("company_name", "").strip()
    if not name:
        return jsonify({"error": "company_name required"}), 400
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT INTO clients(company_name,category,criticality,sector,country_code)"
                " VALUES(?,?,?,?,?)",
                (name,
                 d.get("category",    "partner"),
                 d.get("criticality", "medium"),
                 d.get("sector",      ""),
                 d.get("country_code","").upper()),
            )
        return jsonify({"success": True})
    except (sqlite3.IntegrityError, PgUniqueViolation):
        return jsonify({"error": "Client already exists"}), 409


@bp.route("/api/clients/<int:cid>", methods=["DELETE"])
@require_key
def del_client(cid: int):
    with get_db() as conn:
        conn.execute("DELETE FROM clients WHERE id=?", (cid,))
    return jsonify({"success": True})


# ── IOCs ───────────────────────────────────────────────────────────────────────

@bp.route("/api/iocs")
@require_key
def list_iocs():
    ioc_type = request.args.get("type")
    source   = request.args.get("source")
    limit    = min(int(request.args.get("limit", 300)), 2000)
    q = "SELECT * FROM iocs WHERE 1=1"; p = []
    if ioc_type: q += " AND ioc_type=?";  p.append(ioc_type)
    if source:   q += " AND source=?";    p.append(source)
    q += " ORDER BY first_seen DESC LIMIT ?"; p.append(limit)
    with get_db() as conn:
        rows = conn.execute(q, p).fetchall()
    return jsonify([{**dict(r), "tags": json_or(r["tags"], [])} for r in rows])


@bp.route("/api/iocs", methods=["POST"])
@require_key
def add_ioc():
    d        = request.json or {}
    ioc_type = d.get("ioc_type", "").strip()
    value    = d.get("value",    "").strip()
    if not ioc_type or not value:
        return jsonify({"error": "ioc_type and value required"}), 400
    if ioc_type not in ("ip", "domain", "hash_md5", "hash_sha256", "url", "email"):
        return jsonify({"error": "Invalid ioc_type"}), 400
    try:
        with get_db() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO iocs(ioc_type,value,source,confidence,tlp,tags)"
                " VALUES(?,?,?,?,?,?)",
                (ioc_type, value,
                 d.get("source",     "manual"),
                 int(d.get("confidence", 50)),
                 d.get("tlp",        "amber"),
                 json.dumps(d.get("tags", []))),
            )
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@bp.route("/api/iocs/stats")
@require_key
def ioc_stats():
    with get_db() as conn:
        total  = conn.execute("SELECT COUNT(*) FROM iocs").fetchone()[0]
        by_t   = dict(conn.execute("SELECT ioc_type,COUNT(*) FROM iocs GROUP BY ioc_type").fetchall())
        by_src = dict(conn.execute("SELECT source,COUNT(*) FROM iocs GROUP BY source ORDER BY COUNT(*) DESC").fetchall())
        recent = conn.execute("SELECT COUNT(*) FROM iocs WHERE first_seen>=datetime('now','-24 hours')").fetchone()[0]
        by_fam = dict(conn.execute("SELECT malware_family,COUNT(*) FROM iocs WHERE malware_family!='' GROUP BY malware_family ORDER BY COUNT(*) DESC LIMIT 10").fetchall())
    return jsonify({
        "total": total, "by_type": by_t, "by_source": by_src,
        "recent_24h": recent, "by_family": by_fam,
    })


# ── Ransomware ────────────────────────────────────────────────────────────────

@bp.route("/api/ransomware")
@require_key
def list_ransomware():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM ransomware_incidents ORDER BY created_at DESC LIMIT 200"
        ).fetchall()
    return jsonify([
        {**dict(r), "attack_techniques": json_or(r["attack_techniques"], [])}
        for r in rows
    ])


@bp.route("/api/ransomware/matched")
@require_key
def list_matched_ransomware():
    with get_db() as conn:
        rows = conn.execute(
            "SELECT * FROM ransomware_incidents WHERE is_client_match=1 "
            "ORDER BY created_at DESC LIMIT 100"
        ).fetchall()
    results = []
    for r in rows:
        d = dict(r)
        d["attack_techniques"] = json_or(r["attack_techniques"], [])
        d["match_reason"] = _build_match_reason(d)
        results.append(d)
    return jsonify(results)


def _build_match_reason(incident):
    reasons = []
    method = incident.get("match_method", "")
    if method == "exact":
        reasons.append("Exact name match with tracked client")
    elif method == "containment":
        reasons.append("Partial name containment match")
    elif method == "token":
        reasons.append("Token overlap match on company name")
    elif method == "fuzzy":
        reasons.append("Fuzzy string similarity match")
    confidence = incident.get("match_confidence", 0)
    if confidence:
        reasons.append(f"Confidence: {confidence:.0%}")
    return "; ".join(reasons) if reasons else "Matched via client name similarity"


@bp.route("/api/ransomware/stats")
@require_key
def ransomware_stats():
    with get_db() as conn:
        total   = conn.execute("SELECT COUNT(*) FROM ransomware_incidents").fetchone()[0]
        clients = conn.execute("SELECT COUNT(*) FROM ransomware_incidents WHERE is_client_match=1").fetchone()[0]
        recent  = conn.execute("SELECT COUNT(*) FROM ransomware_incidents WHERE created_at>=datetime('now','-30 days')").fetchone()[0]
        groups  = dict(conn.execute("SELECT ransomware_group,COUNT(*) FROM ransomware_incidents GROUP BY ransomware_group ORDER BY COUNT(*) DESC LIMIT 15").fetchall())
        by_sec  = dict(conn.execute("SELECT activity,COUNT(*) FROM ransomware_incidents WHERE activity!='' AND activity!='None' GROUP BY activity ORDER BY COUNT(*) DESC LIMIT 10").fetchall())
        rec_grp = dict(conn.execute("SELECT ransomware_group,COUNT(*) FROM ransomware_incidents WHERE created_at>=datetime('now','-7 days') GROUP BY ransomware_group ORDER BY COUNT(*) DESC LIMIT 10").fetchall())
    return jsonify({
        "total": total, "client_matches": clients, "recent_30d": recent,
        "groups": groups, "by_sector": by_sec, "recent_7d_groups": rec_grp,
    })


# ── Threat actors / MITRE ─────────────────────────────────────────────────────

@bp.route("/api/threat-actors")
@require_key
def list_actors():
    with get_db() as conn:
        rows = conn.execute("SELECT * FROM threat_actors ORDER BY name").fetchall()
    return jsonify([{
        **dict(r),
        "aliases":        json_or(r["aliases"],        []),
        "target_sectors": json_or(r["target_sectors"], []),
        "ttps":           json_or(r["ttps"],           []),
    } for r in rows])


@bp.route("/api/mitre/techniques")
@require_key
def list_mitre():
    tactic = request.args.get("tactic")
    with get_db() as conn:
        if tactic:
            rows = conn.execute(
                "SELECT * FROM mitre_techniques WHERE tactic=? ORDER BY technique_id",
                (tactic,),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM mitre_techniques ORDER BY technique_id LIMIT 500"
            ).fetchall()
    return jsonify([dict(r) for r in rows])
