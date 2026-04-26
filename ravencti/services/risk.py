"""
services/risk.py — Risk scoring and CVE relevance logic.

calc_risk()     — additive 0-10 score anchored to CVSS (asset context)
priority_score()— weighted CVE priority: CVSS×0.4 + EPSS×0.35 + KEV×0.25
score_cve()     — algorithmic relevance triage (vector + keyword analysis)
explain_risk()  — human-readable risk breakdown for analysts
global_risk()   — aggregate organisational risk score 0-100
"""
import re
from dataclasses import dataclass
from datetime import datetime


# ── Asset-context risk score ───────────────────────────────────────────────────
_CRIT_BONUS: dict = {"low": -1.0, "medium": 0.0, "high": 0.5, "critical": 1.0}
_EXP_BONUS:  dict = {"internal": -1.0, "dmz": 0.0, "external": 0.5}


def calc_risk(
    cvss: float,
    epss: float,
    in_kev: bool,
    has_exploit: bool,
    criticality: str = "medium",
    exposure: str = "external",
) -> tuple:
    """
    Additive risk score 0-10 anchored to CVSS.
    Asset criticality and exposure add at most ±1.5 each —
    context does NOT inflate a medium CVE to critical alone.

    Returns: (score: float, tier: str)
    """
    base  = float(cvss or 0)
    bonus = 0.0
    if in_kev:              bonus += 1.5
    if (epss or 0) >= 0.5:  bonus += 1.0
    elif (epss or 0) >= 0.1: bonus += 0.5
    if has_exploit:         bonus += 0.5
    bonus += _CRIT_BONUS.get(criticality, 0.0)
    bonus += _EXP_BONUS.get(exposure, 0.0)
    score = round(max(0.0, min(10.0, base + bonus)), 2)
    tier  = ("critical" if score >= 9.0 else
             "high"     if score >= 7.0 else
             "medium"   if score >= 4.0 else "low")
    return score, tier


# ── Weighted priority score ────────────────────────────────────────────────────
def priority_score(cvss: float, epss: float, in_kev: bool) -> float:
    """
    Weighted CVE priority score 0-10.

    Formula (research-backed weights):
        CVSS contribution : 40 %   (base technical severity)
        EPSS contribution : 35 %   (empirical exploitation probability)
        KEV  contribution : 25 %   (confirmed active exploitation)

    CVSS is normalised to 0-1 (divide by 10).
    EPSS is already 0-1.
    KEV is binary 0 or 1.

    Examples:
        CVSS 9.8, EPSS 0.97, KEV=True   → (0.98×4 + 0.97×3.5 + 1×2.5) = 9.315
        CVSS 7.5, EPSS 0.10, KEV=False  → (0.75×4 + 0.10×3.5 + 0×2.5) = 3.35
        CVSS 5.0, EPSS 0.01, KEV=False  → (0.50×4 + 0.01×3.5 + 0×2.5) = 2.035
    """
    c = float(cvss or 0) / 10.0
    e = max(0.0, min(1.0, float(epss or 0)))
    k = 1.0 if in_kev else 0.0
    return round(min(10.0, c * 4.0 + e * 3.5 + k * 2.5), 2)


# ── CVE relevance triage ───────────────────────────────────────────────────────
_IMPACT_PATTERNS: list = [
    (r"remote code exec|unauthenticated.{0,30}(execut|upload|access)|execut.{0,20}arbitrary code", 2.0, "RCE"),
    (r"authentication bypass|bypass.{0,20}auth|unauthenticated.{0,20}(bypass|admin)",              1.8, "Auth bypass"),
    (r"command injection|os command|shell injection|code injection",                                1.8, "Command injection"),
    (r"privilege escal|local privilege|elevat.{0,20}privilege",                                    1.5, "Privesc"),
    (r"deserialization|unsafe deseri",                                                              1.4, "Unsafe deserialization"),
    (r"arbitrary file (read|write|upload|delete)|path traversal|directory traversal",              1.3, "File access"),
    (r"sql injection|sqli|blind sql",                                                               1.2, "SQLi"),
    (r"server.side request forgery|ssrf",                                                          1.0, "SSRF"),
    (r"xml external entity|xxe",                                                                   0.9, "XXE"),
    (r"zero.?day|0.?day|actively exploit|in the wild|weaponized",                                  2.0, "Zero-day"),
    (r"denial.of.service|resource exhaustion|infinite loop",                                       0.4, "DoS"),
    (r"information disclosure|sensitive (data|info)|credentials? (exposed|leak)",                 0.6, "Info disclosure"),
    (r"cross.site scripting|xss",                                                                  0.5, "XSS"),
    (r"cross.site request forgery|csrf",                                                           0.3, "CSRF"),
]


@dataclass
class TriageResult:
    score: float
    note:  str
    skip:  bool


def score_cve(
    cve_id: str,
    cvss: float,
    cvss_vector: str,
    description: str,
    in_kev: bool,
    epss: float,
    has_exploit: bool,
    published_date: str,
    skip_threshold: float = 4.0,
) -> TriageResult:
    """
    Algorithmic CVE relevance scorer — pure Python, no external deps.

    Scoring model (additive, clamped 0-10):
      Base:     CVSS/10 × 5.0
      KEV:      +4.0
      EPSS:     up to +2.5
      Vector:   AV:N +1.5, AC:H -1.0, PR:H -1.5, S:C +0.5
      Exploit:  +0.5
      Keywords: up to +2.0
      Recency:  up to +0.5
    """
    score = 0.0
    notes: list = []

    if cvss:
        score += (float(cvss) / 10.0) * 5.0

    if in_kev:
        score += 4.0
        notes.append("CISA KEV")

    ep = float(epss or 0)
    if   ep >= 0.5:  score += 2.5; notes.append(f"EPSS {ep:.0%}")
    elif ep >= 0.2:  score += 2.0; notes.append(f"EPSS {ep:.0%}")
    elif ep >= 0.1:  score += 1.5; notes.append(f"EPSS {ep:.1%}")
    elif ep >= 0.05: score += 0.8
    elif ep >= 0.01: score += 0.3

    vec = (cvss_vector or "").upper()
    if   "/AV:N/" in vec: score += 1.5
    elif "/AV:A/" in vec: score += 0.5
    if "/AC:H/"  in vec: score -= 1.0
    if   "/PR:H/" in vec: score -= 1.5
    elif "/PR:L/" in vec: score -= 0.5
    if "/S:C/"   in vec: score += 0.5
    if "/UI:N/"  in vec: score += 0.3

    if has_exploit:
        score += 0.5
        notes.append("public exploit")

    desc_l = (description or "").lower()
    for pattern, bonus, label in _IMPACT_PATTERNS:
        if re.search(pattern, desc_l):
            score += bonus
            if label not in " ".join(notes):
                notes.append(label)
            break

    matched = [lbl for pat, _, lbl in _IMPACT_PATTERNS if re.search(pat, desc_l)]
    for lbl in matched[1:3]:
        if lbl not in " ".join(notes):
            notes.append(lbl)

    try:
        pub_year = int((published_date or "")[:4])
        age = (datetime.utcnow().year - pub_year) * 365
        if   age <= 365: score += 0.5
        elif age <= 730: score += 0.2
    except (ValueError, TypeError):
        pass

    score = round(max(0.0, min(10.0, score)), 2)
    note  = "; ".join(notes[:4]) if notes else f"CVSS {cvss}"
    return TriageResult(score=score, note=note[:160], skip=score <= skip_threshold)


def explain_risk(cvss, epss, in_kev, has_exploit, criticality="medium",
                 exposure="external") -> dict:
    """Human-readable breakdown of how a risk score was calculated."""
    factors = []
    total = 0.0

    if cvss:
        base = float(cvss)
        factors.append({"factor": "CVSS Base", "value": base, "weight": 1.0,
                        "detail": f"Base severity: {base}/10"})
        total += base

    if in_kev:
        factors.append({"factor": "CISA KEV", "value": 1.5, "weight": 1.0,
                        "detail": "Known exploited vulnerability (active threats)"})
        total += 1.5

    ep = float(epss or 0)
    if ep >= 0.5:
        factors.append({"factor": "EPSS", "value": 1.0, "weight": 1.0,
                        "detail": f"Exploitation probability {ep:.0%} (very high)"})
        total += 1.0
    elif ep >= 0.1:
        factors.append({"factor": "EPSS", "value": 0.5, "weight": 1.0,
                        "detail": f"Exploitation probability {ep:.0%} (elevated)"})
        total += 0.5
    elif ep >= 0.01:
        factors.append({"factor": "EPSS", "value": 0.2, "weight": 0.5,
                        "detail": f"Exploitation probability {ep:.1%} (low)"})
        total += 0.2

    if has_exploit:
        factors.append({"factor": "Public Exploit", "value": 0.5, "weight": 0.8,
                        "detail": "Public exploit code available"})
        total += 0.5

    crit_bonus = _CRIT_BONUS.get(criticality, 0.0)
    if crit_bonus != 0:
        factors.append({"factor": "Asset Criticality", "value": crit_bonus,
                        "weight": 0.6,
                        "detail": f"Asset criticality: {criticality}"})
        total += crit_bonus

    exp_bonus = _EXP_BONUS.get(exposure, 0.0)
    if exp_bonus != 0:
        factors.append({"factor": "Exposure Level", "value": exp_bonus,
                        "weight": 0.6,
                        "detail": f"Exposure: {exposure}"})
        total += exp_bonus

    final = round(max(0.0, min(10.0, total)), 2)
    tier = ("critical" if final >= 9.0 else
            "high" if final >= 7.0 else
            "medium" if final >= 4.0 else "low")

    return {
        "score": final,
        "tier": tier,
        "factors": factors,
        "summary": f"{final}/10 ({tier}) — driven by {factors[0]['factor'] if factors else 'no data'}",
    }


def global_risk(stats: dict) -> dict:
    """
    Aggregate organisational risk score 0-100.

    Factors:
      - Critical CVEs weighted by KEV status
      - Open critical alerts
      - Client ransomware matches
      - Open exposure findings
      - Dark web mentions
    """
    score = 0.0
    factors = []

    cve_stats = stats.get("cves", {})
    critical = cve_stats.get("critical", 0)
    kev = cve_stats.get("kev", 0)
    high_epss = cve_stats.get("high_epss", 0)

    vuln_score = min(critical * 5 + kev * 8 + high_epss * 2, 40)
    if vuln_score > 0:
        factors.append({"factor": "Vulnerability Risk", "value": vuln_score,
                        "detail": f"{critical} critical, {kev} in KEV, {high_epss} high EPSS"})
    score += vuln_score

    alert_stats = stats.get("alerts", {})
    open_alerts = alert_stats.get("open", 0)
    crit_alerts = alert_stats.get("critical", 0)

    alert_score = min(crit_alerts * 10 + open_alerts * 2, 25)
    if alert_score > 0:
        factors.append({"factor": "Alert Load", "value": alert_score,
                        "detail": f"{crit_alerts} critical, {open_alerts} open alerts"})
    score += alert_score

    rw_stats = stats.get("ransomware", {})
    client_matches = rw_stats.get("client_matches", 0)

    rw_score = min(client_matches * 15, 20)
    if rw_score > 0:
        factors.append({"factor": "Ransomware Threat", "value": rw_score,
                        "detail": f"{client_matches} client matches"})
    score += rw_score

    exp_stats = stats.get("exposure", {})
    open_exp = exp_stats.get("open", 0)
    crit_exp = exp_stats.get("critical", 0)

    exp_score = min(crit_exp * 5 + open_exp, 15)
    if exp_score > 0:
        factors.append({"factor": "Exposure Risk", "value": exp_score,
                        "detail": f"{crit_exp} critical, {open_exp} open findings"})
    score += exp_score

    final = round(min(100, max(0, score)), 1)
    level = ("critical" if final >= 75 else
             "high" if final >= 50 else
             "elevated" if final >= 30 else
             "moderate" if final >= 15 else "low")

    return {
        "score": final,
        "level": level,
        "factors": factors,
        "color": ("#ef4444" if final >= 75 else
                  "#f59e0b" if final >= 50 else
                  "#f97316" if final >= 30 else
                  "#3b82f6" if final >= 15 else "#22c55e"),
    }
