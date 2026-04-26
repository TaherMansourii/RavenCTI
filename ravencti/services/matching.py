"""
services/matching.py — CVE-to-product matching, client name matching, MITRE mapping.
"""
import json
import re
from difflib import SequenceMatcher

from ravencti.utils.helpers import normalise_company


# ── MITRE ATT&CK pattern mapping ───────────────────────────────────────────────
_CVE_PATTERNS: list[tuple[str, str, str, str]] = [
    (r"sql\s+injection|sqli",               "T1190", "Exploit Public-Facing Application", "Initial Access"),
    (r"remote\s+code\s+exec|rce\b",         "T1190", "Exploit Public-Facing Application", "Initial Access"),
    (r"command\s+injection",                 "T1059", "Command and Scripting Interpreter",  "Execution"),
    (r"privilege\s+escal|privesc",           "T1068", "Exploitation for Privilege Escalation", "Privilege Escalation"),
    (r"buffer\s+overflow|heap\s+overflow",   "T1203", "Exploitation for Client Execution",  "Execution"),
    (r"path\s+traversal|directory\s+traversal", "T1083", "File and Directory Discovery",   "Discovery"),
    (r"auth(?:entication)?\s+bypass",        "T1078", "Valid Accounts",                     "Defense Evasion"),
    (r"cross.site\s+scripting|xss\b",        "T1189", "Drive-by Compromise",               "Initial Access"),
    (r"denial.of.service|\bdos\b|\bddos\b",  "T1499", "Endpoint Denial of Service",         "Impact"),
    (r"credential|password\s+hash",          "T1555", "Credentials from Password Stores",   "Credential Access"),
    (r"hardcoded?\s+(?:credential|password|secret|key)", "T1552", "Unsecured Credentials", "Credential Access"),
]

_RW_TTP: dict[str, list[str]] = {
    "lockbit":    ["T1486","T1490","T1562","T1027","T1078","T1021"],
    "blackcat":   ["T1486","T1069","T1083","T1021","T1048"],
    "alphv":      ["T1486","T1069","T1083","T1021","T1048"],
    "clop":       ["T1486","T1041","T1190","T1048","T1566"],
    "blackbasta": ["T1486","T1490","T1059","T1078","T1021"],
    "akira":      ["T1486","T1562","T1190","T1071","T1078"],
    "ransomhub":  ["T1486","T1490","T1059","T1048","T1041"],
    "play":       ["T1486","T1490","T1562","T1078","T1021"],
    "medusa":     ["T1486","T1490","T1059","T1082"],
    "default":    ["T1486","T1490","T1489"],
}

_RW_NATION: dict[str, str] = {
    "lockbit": "Russia", "blackcat": "Russia", "alphv": "Russia",
    "clop": "Russia", "blackbasta": "Russia", "conti": "Russia",
    "revil": "Russia", "darkside": "Russia",
    "lazarus": "North Korea", "kimsuky": "North Korea",
    "apt41": "China", "hafnium": "China",
    "default": "Unknown",
}


def map_attack(description: str) -> dict:
    """Map CVE description to MITRE ATT&CK techniques and tactics."""
    seen: set[str] = set()
    techniques: list[dict] = []
    tactics: set[str] = set()
    dl = description.lower()
    for pat, tid, tname, tact in _CVE_PATTERNS:
        if tid not in seen and re.search(pat, dl):
            techniques.append({"id": tid, "name": tname})
            tactics.add(tact)
            seen.add(tid)
    return {"techniques": techniques, "tactics": list(tactics)}


def map_rw_ttps(group: str) -> list[str]:
    """Return known TTPs for a ransomware group."""
    key = re.sub(r"[^a-z]", "", group.lower().split()[0]) if group else "default"
    return _RW_TTP.get(key, _RW_TTP["default"])


def actor_nation(group: str) -> str:
    """Return likely nation-state attribution for a ransomware group."""
    key = re.sub(r"[^a-z]", "", group.lower().split()[0]) if group else "default"
    return _RW_NATION.get(key, _RW_NATION["default"])


# ── Client name matching ───────────────────────────────────────────────────────
def match_client(
    victim: str,
    clients: list[dict],
) -> tuple[dict | None, float, str]:
    """
    Fuzzy match a ransomware victim name against tracked clients.

    Returns (client_dict | None, confidence 0-1, method_str).
    Confidence threshold: 0.65.
    """
    vn = normalise_company(victim)
    if len(vn) < 4:
        return None, 0.0, ""

    vt = [t for t in vn.split() if len(t) > 3]
    best, best_score, best_method = None, 0.0, ""

    for cl in clients:
        cn = normalise_company(cl["name"])
        if len(cn) < 4:
            continue
        ct = [t for t in cn.split() if len(t) > 3]

        # Exact
        if vn == cn:
            return cl, 1.0, "exact"

        # Containment
        if len(cn) >= 6 and len(vn) >= 6 and (cn in vn or vn in cn):
            score = len(min(vn, cn, key=len)) / max(len(max(vn, cn, key=len)), 1)
            if score > best_score:
                best, best_score, best_method = cl, score, "containment"

        # Token overlap
        if len(ct) >= 2 and len(vt) >= 1:
            score = (sum(1 for t in ct if t in vt) / len(ct)) * 0.90
            if score >= 0.70 and score > best_score:
                best, best_score, best_method = cl, score, "token"

        # Fuzzy
        fuzz = SequenceMatcher(None, vn, cn).ratio()
        if fuzz >= 0.88:
            score = fuzz * 0.80
            if score > best_score:
                best, best_score, best_method = cl, score, "fuzzy"

    if best_score >= 0.65:
        return best, round(best_score, 3), best_method
    return None, 0.0, ""


# ── CPE / product matching ─────────────────────────────────────────────────────
def _cpe_entries(cve_obj: dict) -> list[tuple[str, str, str]]:
    """Extract (vendor, product, raw_cpe) tuples from NVD CVE configurations."""
    out: list[tuple[str, str, str]] = []
    seen: set[str] = set()

    def _proc(node: dict) -> None:
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
            _proc(child)

    for cfg in cve_obj.get("configurations", []):
        for node in cfg.get("nodes", []):
            _proc(node)
    return out


def match_product(cve_obj: dict, products: list[dict]) -> dict | None:
    """Return the first tracked product matched by CPE in a CVE object."""
    entries = _cpe_entries(cve_obj)
    if not entries:
        return None
    for prod in products:
        mp = prod["name"].lower().strip()
        mv = prod["vendor"].lower().strip()
        mv_slug = mv.replace(" ", "").replace("-", "")
        mt = [t for t in mp.split() if len(t) > 2]
        for cv, cp, _raw in entries:
            cv_slug = cv.replace(" ", "").replace("-", "")
            if mp == cp:
                return prod
            if len(mp) >= 4 and len(cp) >= 4 and (mp in cp or cp in mp):
                return prod
            if (mv in cv or cv in mv or mv_slug in cv_slug or cv_slug in mv_slug) and mv:
                ct = [t for t in cp.split() if len(t) > 2]
                if mt and ct and any(t in ct for t in mt):
                    return prod
            if not mv and len(mp) >= 5 and (mp in cp or cp in mp):
                return prod
    return None
