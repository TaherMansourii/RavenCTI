"""
collectors/cve.py — NVD CVE collection + KEV enrichment + EPSS scoring.

DEPLOYMENT: after copying this file, delete stale bytecode with:
    find . -path "*/collectors/__pycache__/cve*.pyc" -delete
Then restart the app. Confirm the new file is loaded by checking the log
for the line: "[NVD] cve.py loaded — min_cvss=4.0"
"""
# ── pyc self-invalidation ────────────────────────────────────────────────────
# Delete our own compiled bytecode on every import so a stale .pyc can never
# shadow this source file.
import pathlib as _pathlib
_self = _pathlib.Path(__file__)
for _pyc in _self.parent.glob(f"__pycache__/{_self.stem}.*.pyc"):
    try:
        _pyc.unlink()
    except OSError:
        pass
# ─────────────────────────────────────────────────────────────────────────────

import json
import logging
import os
import re
import time
from datetime import datetime, timedelta, timezone
from difflib import SequenceMatcher

from ravencti.collectors.base import job_start, job_done, update_source
from ravencti.config import (
    NVD_API_KEY, NVD_URL, KEV_URL, EPSS_URL,
    CVE_MIN_YEAR, CVE_AI_SKIP_THRESHOLD,
)
# CVE_MIN_CVSS intentionally NOT imported from config.
# We default to 4.0 so medium-severity CVEs are collected.
# Override at runtime: CVE_MIN_CVSS=5.0 python app.py
from ravencti.db.connection import get_db
from ravencti.services.matching import map_attack
from ravencti.services.risk import calc_risk, score_cve, priority_score
from ravencti.utils.helpers import safe_str, now_str
from ravencti.utils.http import get_session, safe_get

log = logging.getLogger("ravencti.collectors.cve")

_NVD_HEADERS: dict = {"User-Agent": "RavenCTI/8.0"}
if NVD_API_KEY:
    _NVD_HEADERS["apiKey"] = NVD_API_KEY

_NVD_SLEEP          = 0.6 if NVD_API_KEY else 6.5
_LOOKBACK_DAYS      = int(os.environ.get("CVE_LOOKBACK_DAYS", "7"))
_EFFECTIVE_MIN_CVSS = float(os.environ.get("CVE_MIN_CVSS", "4.0"))

# This line proves the new file is loaded — check for it in your log.
log.info("[NVD] cve.py loaded — min_cvss=%.1f  lookback=%dd  file=%s",
         _EFFECTIVE_MIN_CVSS, _LOOKBACK_DAYS, __file__)

_STOP_WORDS = frozenset({
    "server", "client", "service", "system", "enterprise", "community",
    "platform", "suite", "manager", "management", "software", "application",
    "version", "edition", "product", "module", "plugin", "extension",
})


# ══════════════════════════════════════════════════════════════════════════════
# Main entry point
# ══════════════════════════════════════════════════════════════════════════════

def collect_cves() -> None:
    jid = job_start("cve_collection")
    try:
        products = _get_products()
        if not products:
            job_done(jid, "failed", 0, "No products configured")
            log.warning("[NVD] No products — add technologies in Assets first")
            return

        session = get_session(_NVD_HEADERS)
        n_new = n_skip = n_filtered = 0
        seen: set[str] = set()

        now_utc  = datetime.now(timezone.utc)
        end_dt   = now_utc.strftime("%Y-%m-%dT%H:%M:%S.000")
        start_dt = (now_utc - timedelta(days=_LOOKBACK_DAYS)).strftime("%Y-%m-%dT%H:%M:%S.000")

        log.info(
            "[NVD] Scan | %d products | window %s → %s (%d days) | min_cvss=%.1f",
            len(products), start_dt[:10], end_dt[:10], _LOOKBACK_DAYS, _EFFECTIVE_MIN_CVSS,
        )

        base_params = {
            "lastModStartDate": start_dt,
            "lastModEndDate":   end_dt,
            "noRejected":       "",
        }

        products_cpe     = [p for p in products if (p.get("cpe_prefix") or "").strip()]
        products_keyword = [p for p in products if not (p.get("cpe_prefix") or "").strip()]

        if products_keyword:
            log.info(
                "[NVD] %d product(s) without cpe_prefix (using keywordSearch): %s",
                len(products_keyword),
                ", ".join(p["name"] for p in products_keyword),
            )

        # Phase 1 — CPE queries (precise)
        for prod in products_cpe:
            cpe = prod["cpe_prefix"].strip().rstrip("*").rstrip(":")
            log.info("[NVD] cpeName  %s/%s", prod["vendor"], prod["name"])
            vulns = _nvd_fetch_all({**base_params, "cpeName": cpe + ":*:*:*:*:*:*:*:*"}, session)
            log.info("[NVD]   fetched=%d", len(vulns))
            new, skip, filtered = _process_batch(vulns, [prod], seen, "cpe")
            n_new += new; n_skip += skip; n_filtered += filtered
            log.info("[NVD]   stored=%d  skipped=%d  filtered=%d", new, skip, filtered)
            time.sleep(_NVD_SLEEP)

        # Phase 2 — keyword queries (fallback)
        for prod in products_keyword:
            keyword = _build_keyword(prod)
            log.info("[NVD] keyword  %s/%s  → '%s'", prod["vendor"], prod["name"], keyword)
            if not keyword.strip():
                log.warning("[NVD] Empty keyword for %s/%s — skipping",
                            prod["vendor"], prod["name"])
                continue
            vulns = _nvd_fetch_all({**base_params, "keywordSearch": keyword}, session)
            log.info("[NVD]   fetched=%d", len(vulns))
            new, skip, filtered = _process_batch(vulns, products, seen, "keyword")
            n_new += new; n_skip += skip; n_filtered += filtered
            log.info("[NVD]   stored=%d  skipped=%d  filtered=%d", new, skip, filtered)
            time.sleep(_NVD_SLEEP)

        log.info(
            "[NVD] Done — new=%d  triage-skipped=%d  hard-filtered=%d",
            n_new, n_skip, n_filtered,
        )
        if n_new == 0:
            log.warning(
                "[NVD] 0 new CVEs stored. Causes: no CVEs in 7-day window, "
                "CVSS threshold %.1f too high, or NVD unreachable.",
                _EFFECTIVE_MIN_CVSS,
            )

        update_source("nvd", "success", n_new)
        job_done(jid, "completed", n_new)

        from ravencti.services.queue import enqueue
        enqueue(collect_kev,  "kev")
        enqueue(collect_epss, "epss")

    except Exception as e:
        update_source("nvd", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_cves failed")


# ══════════════════════════════════════════════════════════════════════════════
# Per-batch processing pipeline
# ══════════════════════════════════════════════════════════════════════════════

def _process_batch(
    vulns:    list,
    products: list,
    seen:     set,
    method:   str,
) -> tuple:
    """
    Filter → match → dedup → store → triage.
    Returns (new_stored, triage_skipped, hard_filtered).
    """

    n_new = n_skip = n_filtered = 0
    pending: list = []

    # 🔥 NEW: group CVEs per product before inserting
    product_buckets = {}

    with get_db() as conn:
        for vuln in vulns:
            cve_obj = vuln.get("cve", {})
            cve_id  = cve_obj.get("id")
            if not cve_id:
                continue

            cvss, sev, vec = _parse_cvss(cve_obj.get("metrics", {}))

            # 🔒 STRICT FILTER ≥ 7 ONLY
            if cvss is None or cvss < 5.0:
                n_filtered += 1
                continue

            if _published_year(cve_obj) < CVE_MIN_YEAR:
                n_filtered += 1
                continue

            if not _version_range_ok(cve_obj):
                n_filtered += 1
                continue

            # Product matching
            if method == "cpe":
                matched = [(products[0], "cpe")]
            else:
                matched = _match_products(cve_obj, products)
                if not matched:
                    n_filtered += 1
                    continue

            # 🔥 Assign CVE to each matched product bucket
            for prod, _ in matched:
                pid = prod.get("id")

                if pid not in product_buckets:
                    product_buckets[pid] = []

                product_buckets[pid].append((cve_obj, prod, cvss, vec, sev))

    # =========================
    # 🔥 LIMIT PER PRODUCT
    # =========================
    MAX_PER_PRODUCT = 2  # 👈 adjust here

    with get_db() as conn:
        for pid, cves in product_buckets.items():

            # 🔥 sort by CVSS DESC + newest first
            cves.sort(
                key=lambda x: (
                    x[2],  # cvss
                    safe_str(x[0].get("published"))
                ),
                reverse=True
            )

            # 🔥 keep only top N
            for cve_obj, prod, cvss, vec, sev in cves[:MAX_PER_PRODUCT]:
                cve_id = cve_obj.get("id")

                if cve_id in seen:
                    continue

                stored_id, is_new = _store_cve(conn, cve_obj, [(prod, "filtered")])

                if stored_id:
                    seen.add(stored_id)

                    if is_new:
                        n_new += 1
                        pending.append((
                            cve_id, cvss, vec or "", sev,
                            _desc(cve_obj), False, 0.0, False,
                            safe_str(cve_obj.get("published")),
                        ))

    if pending:
        n_skip += _triage(pending)

    return n_new, n_skip, n_filtered

# ══════════════════════════════════════════════════════════════════════════════
# Product matching
# ══════════════════════════════════════════════════════════════════════════════

def _clean(s: str) -> str:
    """Strip DB artefacts: leading slash, trailing dot from CPE copy-paste."""
    return (s or "").strip().strip("/\\._-,;:!?")


def _normalise(s: str) -> str:
    s = _clean(s).lower()
    s = re.sub(r"[_\-./]", " ", s)
    s = re.sub(r"\b(inc|llc|ltd|corp|gmbh|sa|ag|plc)\.?\b", "", s)
    return re.sub(r"\s+", " ", s).strip()


def _slug(s: str) -> str:
    """All-lowercase alphanumeric only — for fuzzy slug matching."""
    return re.sub(r"[^a-z0-9]", "", _normalise(s))


def _tokens(s: str) -> set:
    return {t for t in _normalise(s).split() if len(t) >= 3 and t not in _STOP_WORDS}


def _cpe_entries(cve_obj: dict) -> list:
    """Return (vendor, product, raw_cpe) for every vulnerable CPE match."""
    out: list = []
    seen: set = set()

    def _walk(node):
        for m in node.get("cpeMatch", []):
            if not m.get("vulnerable"):
                continue
            raw = m.get("criteria", "")
            if raw in seen:
                continue
            seen.add(raw)
            parts = raw.split(":")
            if len(parts) >= 5:
                v = parts[3].replace("_", " ").lower().strip()
                p = parts[4].replace("_", " ").lower().strip()
                if v not in ("*", "", "na") and p not in ("*", "", "na"):
                    out.append((v, p, raw))
        for child in node.get("children", []):
            _walk(child)

    for cfg in cve_obj.get("configurations", []):
        for node in cfg.get("nodes", []):
            _walk(node)
    return out


def _score_product_match(cve_obj: dict, prod: dict, cpe_entries: list) -> float:
    """
    Score 0.0–1.0 for how strongly a tracked product matches a CVE.

    CPE signals (require NVD to have enriched the CVE with CPE data):
      1.0  exact vendor + product match
      0.9  exact product name or slug
      0.8  full token overlap (all tokens match)
      0.7  token overlap ≥ 80%
      0.6  fuzzy name similarity ≥ 0.85
      0.5  product tokens are a subset of CPE tokens
      0.45 vendor slug containment + any product token overlap

    Description fallback (for brand-new CVEs with no CPE data yet):
      0.80 exact raw product name in description  ("gdk-pixbuf" in text)
      0.75 normalised product name in description ("gdk pixbuf" in text)
      0.70 product slug in de-punctuated description ("gdkpixbuf" in text)
      0.60 all product tokens present as whole words in description
      0.50 single long token (≥6 chars) present as a whole word

    Acceptance threshold: 0.35
    """
    pname = _normalise(prod.get("name", ""))
    pvend = _normalise(prod.get("vendor", ""))
    ptoks = _tokens(prod.get("name", ""))
    vtoks = _tokens(prod.get("vendor", ""))
    pslug = _slug(prod.get("name", ""))
    vslug = _slug(prod.get("vendor", ""))
    # Keep the raw cleaned name for description matching (preserves hyphens)
    praw  = _clean(prod.get("name", "")).lower()
    best  = 0.0

    for cv, cp, _raw in cpe_entries:
        cpe_v     = _normalise(cv)
        cpe_p     = _normalise(cp)
        cpe_vtoks = _tokens(cv)
        cpe_ptoks = _tokens(cp)
        cpe_pslug = _slug(cp)
        cpe_vslug = _slug(cv)
        score = 0.0

        # Exact vendor + product
        if pvend and pname and cpe_v == pvend and cpe_p == pname:
            score = max(score, 1.0)
        # Exact product name
        if pname and cpe_p == pname:
            score = max(score, 0.9)
        # Slug exact match
        if pslug and cpe_pslug and pslug == cpe_pslug:
            score = max(score, 0.9)
        # Token overlap
        if ptoks and cpe_ptoks:
            overlap = len(ptoks & cpe_ptoks) / max(len(ptoks), len(cpe_ptoks))
            if overlap >= 1.0:
                score = max(score, 0.8)
            elif overlap >= 0.80:
                vboost = 0.1 if (vtoks and cpe_vtoks and
                    len(vtoks & cpe_vtoks) / max(len(vtoks), len(cpe_vtoks)) >= 0.5) else 0.0
                score = max(score, 0.70 + vboost)
        # Fuzzy similarity
        if pname and len(pname) >= 4 and len(cpe_p) >= 4:
            sim = SequenceMatcher(None, pname, cpe_p).ratio()
            if sim >= 0.85:
                score = max(score, 0.6)
            elif sim >= 0.75 and pvend:
                vsim = SequenceMatcher(None, pvend, cpe_v).ratio()
                if vsim >= 0.70:
                    score = max(score, 0.5)
        # Token subset
        if ptoks and cpe_ptoks and ptoks.issubset(cpe_ptoks | {t[:6] for t in cpe_ptoks}):
            score = max(score, 0.5)
        # Vendor slug containment + product token overlap
        if vslug and len(vslug) >= 4 and (vslug in cpe_vslug or cpe_vslug in vslug):
            if ptoks & cpe_ptoks:
                score = max(score, 0.45)

        best = max(best, score)
        if best >= 0.9:
            break

    # ── Description fallback ─────────────────────────────────────────────────
    # Brand-new CVEs from CNAs (e.g. Red Hat) often have no CPE data yet.
    # NVD returned this CVE because our keyword matched — a clear product
    # name hit in the description is strong enough to accept it.
    if best < 0.35 and len(pname) >= 4:
        desc      = _desc(cve_obj).lower()
        desc_slug = re.sub(r"[^a-z0-9]", "", desc)
        desc_toks = set(re.findall(r"\b\w+\b", desc))

        if praw and praw in desc:
            # "gdk-pixbuf" literally in description
            best = max(best, 0.80)
        elif pname and pname in desc:
            # "gdk pixbuf" (normalised, spaces) in description
            best = max(best, 0.75)
        elif pslug and len(pslug) >= 5 and pslug in desc_slug:
            # "gdkpixbuf" in description stripped of punctuation
            best = max(best, 0.70)
        elif len(ptoks) >= 2 and ptoks.issubset(desc_toks):
            # All tokens present as whole words: {"gdk", "pixbuf"} ⊆ desc words
            best = max(best, 0.60)
        elif len(ptoks) == 1 and ptoks.issubset(desc_toks) and len(list(ptoks)[0]) >= 6:
            # Single long token present as a whole word
            best = max(best, 0.50)

    return round(best, 3)


def _match_products(cve_obj: dict, products: list) -> list:
    """
    Return [(product, method)] sorted by score descending.
    Acceptance threshold: 0.35
    """
    THRESHOLD = 0.35
    entries   = _cpe_entries(cve_obj)
    scored    = []

    log.info("[MATCH] %s — CPE entries=%d, checking %d product(s)",
             cve_obj.get("id"), len(entries), len(products))

    for prod in products:
        s = _score_product_match(cve_obj, prod, entries)
        verdict = "ACCEPTED" if s >= THRESHOLD else "rejected"
        log.info("[MATCH]   %s ↔ %s/%s  score=%.3f  cpe_data=%s  → %s",
                 cve_obj.get("id"),
                 prod.get("vendor"), prod.get("name"),
                 s, bool(entries), verdict)
        if s >= THRESHOLD:
            method = "cpe_match" if s >= 0.6 else "desc_match"
            scored.append((s, prod, method))

    scored.sort(key=lambda x: x[0], reverse=True)
    return [(prod, method) for _, prod, method in scored]


# ══════════════════════════════════════════════════════════════════════════════
# Storage
# ══════════════════════════════════════════════════════════════════════════════

def _store_cve(conn, cve_obj: dict, products_matched: list) -> tuple:
    cve_id = cve_obj.get("id")
    if not cve_id or not products_matched:
        return None, False

    desc = _desc(cve_obj)
    cvss, sev, vec = _parse_cvss(cve_obj.get("metrics", {}))
    cwes = list({
        d["value"] for w in cve_obj.get("weaknesses", [])
        for d in w.get("description", []) if d.get("value", "").startswith("CWE-")
    })
    atk = map_attack(desc)

    best_prod, best_s = products_matched[0][0], 0.0
    for prod, _ in products_matched:
        s, _ = calc_risk(cvss or 0, 0, False, False,
                         prod.get("criticality", "medium"), prod.get("exposure", "external"))
        if s > best_s:
            best_s, best_prod = s, prod

    primary_s, primary_t = calc_risk(
        cvss or 0, 0, False, False,
        best_prod.get("criticality", "medium"), best_prod.get("exposure", "external"),
    )
    pri = priority_score(cvss or 0, 0.0, False)

    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO cves"
            "(cve_id,product_id,product,vendor,cvss_score,cvss_vector,severity,"
            " description,published_date,url,cwe_ids,attack_techniques,attack_tactics,"
            " is_product_match,risk_score,risk_tier,ai_relevance,created_at)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?,?,?,?)",
            (cve_id, best_prod.get("id"), best_prod["name"], best_prod["vendor"],
             cvss, safe_str(vec), (sev or "UNKNOWN").upper(), desc[:600],
             safe_str(cve_obj.get("published")),
             f"https://nvd.nist.gov/vuln/detail/{cve_id}",
             json.dumps(cwes),
             json.dumps([x["id"] for x in atk["techniques"]]),
             json.dumps(atk["tactics"]),
             primary_s, primary_t, pri, now_str()),
        )
        is_new = cur.rowcount > 0
        if is_new:
            log.info("[NVD] STORED %s  cvss=%.1f  product=%s",
                     cve_id, cvss or 0, best_prod["name"])
        else:
            log.info("[NVD] DUPLICATE %s already in DB", cve_id)
    except Exception as e:
        log.warning("[NVD] Insert failed %s: %s", cve_id, e)
        return cve_id, False

    for prod, method in products_matched:
        s, t = calc_risk(cvss or 0, 0, False, False,
                         prod.get("criticality", "medium"), prod.get("exposure", "external"))
        try:
            conn.execute(
                "INSERT OR IGNORE INTO cve_products"
                "(cve_id,product_id,product_name,risk_score,risk_tier,match_method)"
                " VALUES(?,?,?,?,?,?)",
                (cve_id, prod.get("id"), prod["name"], s, t, method),
            )
        except Exception:
            pass

    return cve_id, is_new

# ══════════════════════════════════════════════════════════════════════════════
# Triage
# ══════════════════════════════════════════════════════════════════════════════

def _triage(batch: list) -> int:
    skipped = 0
    with get_db() as conn:
        for row in batch:
            cve_id, cvss, vec, sev, desc, in_kev, epss, has_exp, pub = row
            result = score_cve(cve_id, cvss, vec, desc, in_kev, epss, has_exp, pub,
                               skip_threshold=CVE_AI_SKIP_THRESHOLD)
            pri = priority_score(cvss, epss, in_kev)
            conn.execute(
                "UPDATE cves SET ai_relevance=?, ai_note=?, ai_skip=?, risk_score=? WHERE cve_id=?",
                (result.score, result.note, 1 if result.skip else 0, pri, cve_id),
            )
            if result.skip:
                skipped += 1
    return skipped


# ══════════════════════════════════════════════════════════════════════════════
# KEV enrichment
# ══════════════════════════════════════════════════════════════════════════════

def collect_kev() -> None:
    jid = job_start("kev_enrichment")
    try:
        session = get_session()
        r = safe_get(KEV_URL, session=session, timeout=30)
        if r is None or r.status_code != 200:
            raise RuntimeError(f"KEV fetch failed: {getattr(r, 'status_code', 'no response')}")

        kev = {v["cveID"]: v["dateAdded"] for v in r.json().get("vulnerabilities", [])}
        n   = 0

        with get_db() as conn:
            for row in conn.execute(
                "SELECT id, cve_id, cvss_score, epss_score, product_id FROM cves"
            ).fetchall():
                if row["cve_id"] not in kev:
                    continue
                pr = conn.execute(
                    "SELECT criticality, exposure FROM products WHERE id=?",
                    (row["product_id"],),
                ).fetchone()
                s, t = calc_risk(
                    row["cvss_score"] or 0, row["epss_score"] or 0, True, False,
                    pr["criticality"] if pr else "medium",
                    pr["exposure"]    if pr else "external",
                )
                pri = priority_score(row["cvss_score"] or 0, row["epss_score"] or 0, True)
                conn.execute(
                    "UPDATE cves SET in_cisa_kev=1, kev_date_added=?, "
                    "risk_score=?, risk_tier=?, ai_relevance=?, enriched_at=? WHERE id=?",
                    (kev[row["cve_id"]], s, t, pri, now_str(), row["id"]),
                )
                n += 1

        log.info("[KEV] Enriched %d CVEs", n)
        if n == 0:
            log.warning("[KEV] 0 CVEs matched KEV — run CVE scan first")

        update_source("cisa_kev", "success", n)
        job_done(jid, "completed", n)

        from ravencti.services.alerts import run_alerts
        run_alerts()

    except Exception as e:
        update_source("cisa_kev", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_kev failed")


# ══════════════════════════════════════════════════════════════════════════════
# EPSS enrichment
# ══════════════════════════════════════════════════════════════════════════════

def collect_epss() -> None:
    jid = job_start("epss_enrichment")
    try:
        with get_db() as conn:
            ids = [r[0] for r in conn.execute("SELECT cve_id FROM cves").fetchall()]

        if not ids:
            log.warning("[EPSS] No CVEs in DB to enrich")
            job_done(jid, "completed", 0)
            return

        session = get_session()
        data: dict = {}
        for i in range(0, len(ids), 100):
            r = safe_get(EPSS_URL, session=session,
                         params={"cve": ",".join(ids[i:i+100])}, timeout=30)
            if r and r.status_code == 200:
                for e in r.json().get("data", []):
                    data[e["cve"]] = {"epss": float(e.get("epss", 0)),
                                      "pct":  float(e.get("percentile", 0))}
            time.sleep(0.5)

        n = 0
        with get_db() as conn:
            for cid, ep in data.items():
                row = conn.execute(
                    "SELECT id, cvss_score, in_cisa_kev, product_id FROM cves WHERE cve_id=?",
                    (cid,)).fetchone()
                if not row:
                    continue
                pr = conn.execute(
                    "SELECT criticality, exposure FROM products WHERE id=?",
                    (row["product_id"],)).fetchone()
                s, t = calc_risk(
                    row["cvss_score"] or 0, ep["epss"], bool(row["in_cisa_kev"]), False,
                    pr["criticality"] if pr else "medium",
                    pr["exposure"]    if pr else "external")
                pri = priority_score(row["cvss_score"] or 0, ep["epss"], bool(row["in_cisa_kev"]))
                conn.execute(
                    "UPDATE cves SET epss_score=?, epss_percentile=?, "
                    "risk_score=?, risk_tier=?, ai_relevance=?, enriched_at=? WHERE id=?",
                    (ep["epss"], ep["pct"], s, t, pri, now_str(), row["id"]))
                n += 1

        log.info("[EPSS] Updated %d CVEs", n)
        if n == 0:
            log.warning("[EPSS] 0 CVEs updated — check EPSS API")

        update_source("first_epss", "success", n)
        job_done(jid, "completed", n)

    except Exception as e:
        update_source("first_epss", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_epss failed")


# ══════════════════════════════════════════════════════════════════════════════
# NVD pagination
# ══════════════════════════════════════════════════════════════════════════════

def _nvd_fetch_all(params: dict, session, timeout: int = 90) -> list:
    vulns: list = []
    start = 0
    per   = 2000

    for page in range(10):
        p = {**params, "startIndex": start, "resultsPerPage": per}
        r = safe_get(NVD_URL, session=session, params=p, timeout=timeout)

        if r is None:
            log.warning("[NVD] No response on page %d", page)
            break
        if r.status_code == 403:
            log.warning("[NVD] 403 rate-limited — sleeping 35s")
            time.sleep(35)
            r = safe_get(NVD_URL, session=session, params=p, timeout=timeout)
            if r is None or r.status_code != 200:
                break
        if r.status_code != 200:
            log.warning("[NVD] HTTP %d on page %d", r.status_code, page)
            break

        data  = r.json()
        batch = data.get("vulnerabilities", [])
        total = data.get("totalResults", 0)
        vulns.extend(batch)
        start += len(batch)
        log.debug("[NVD] Page %d: %d/%d", page, start, total)

        if start >= total or not batch:
            break
        time.sleep(_NVD_SLEEP)

    return vulns


# ══════════════════════════════════════════════════════════════════════════════
# CVE object helpers
# ══════════════════════════════════════════════════════════════════════════════

def _parse_cvss(metrics: dict) -> tuple:
    for ver in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        ml = metrics.get(ver)
        if ml:
            d = ml[0].get("cvssData", {})
            score = d.get("baseScore")
            if score:
                return (float(score),
                        d.get("baseSeverity", "UNKNOWN").upper(),
                        d.get("vectorString", ""))
    return None, "UNKNOWN", ""


def _published_year(cve_obj: dict) -> int:
    try:
        return int((cve_obj.get("published") or "")[:4])
    except (ValueError, TypeError):
        return 9999


def _version_range_ok(cve_obj: dict) -> bool:
    end_years: list = []
    for cfg in cve_obj.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                if not m.get("vulnerable", True):
                    continue
                for field in ("versionEndExcluding", "versionEndIncluding"):
                    v = m.get(field, "")
                    if v and re.match(r"^\d{4}", v):
                        try:
                            end_years.append(int(v[:4]))
                        except ValueError:
                            pass
    return not (end_years and all(y < CVE_MIN_YEAR for y in end_years))


def _desc(cve_obj: dict) -> str:
    return next(
        (d["value"] for d in cve_obj.get("descriptions", []) if d.get("lang") == "en"),
        "",
    )


def _build_keyword(prod: dict) -> str:
    """Build NVD keyword, sanitising DB artefacts like leading slash."""
    vendor = _clean(prod.get("vendor") or "")
    name   = _clean(prod.get("name")   or "")
    if vendor and vendor.lower() not in ("unknown", "open source", "community", ""):
        if _normalise(vendor) == _normalise(name):
            return name   # avoid "tenda tenda" duplication
        return f"{vendor} {name}"
    return name


def _get_products() -> list:
    with get_db() as conn:
        rows = conn.execute(
            "SELECT id, product_name as name, vendor, criticality, exposure, cpe_prefix "
            "FROM products"
        ).fetchall()
        products = [dict(r) for r in rows]
        log.info("[NVD] Loaded %d product(s): %s",
                 len(products),
                 [(p.get("vendor"), p.get("name")) for p in products])
        return products