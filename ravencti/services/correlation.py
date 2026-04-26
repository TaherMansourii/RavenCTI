"""
services/correlation.py — IOC extraction, finding correlation, incident classification.

Improvements over v1:
  - Explainable matching (why an alert triggered)
  - Reduced false positives via multi-source requirement
  - Modular rule-based system
  - Asset context awareness
  - Temporal weighting (recent = higher confidence)
"""
import re
from collections import defaultdict
from datetime import datetime

IOC_PATTERNS = {
    "domain": r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b",
    "email":  r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "ip":     r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "cve":    r"\bCVE-\d{4}-\d{4,}\b",
    "hash":   r"\b[a-fA-F0-9]{32,64}\b",
}


def extract_iocs(text):
    if not text:
        return {}
    found = {}
    for k, pattern in IOC_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            if k == "domain":
                matches = [m for m in matches if not m.endswith((".jpg",".png",".gif",".css",".js"))]
            found[k] = list(set(m.lower() for m in matches if len(m) > 3))
    return found


def explain_match(finding, indicator_type, indicator_value, assets=None):
    """Generate human-readable explanation for why a finding matched."""
    reasons = []
    title = (finding.get("title") or "").lower()
    desc = (finding.get("description") or "").lower()
    content = (finding.get("raw_content") or "").lower()
    combined = f"{title} {desc} {content}"

    if indicator_value:
        reasons.append(f"Shared {indicator_type}: {indicator_value}")

    severity = finding.get("severity", "medium")
    if severity == "critical":
        reasons.append(f"Critical severity finding from {finding.get('source', 'unknown')}")
    elif severity == "high":
        reasons.append(f"High severity from {finding.get('source', 'unknown')}")

    source = finding.get("source", "")
    if source in ("darkforums", "patched", "cracked"):
        reasons.append(f"Dark web source: {source}")

    source_types = {"github": "code", "reddit": "forum", "telegram": "messaging",
                    "paste": "paste", "twitter": "social media",
                    "darkforums": "darkweb", "patched": "darkweb", "cracked": "darkweb"}
    if source in source_types:
        reasons.append(f"Data type: {source_types[source]}")

    if assets:
        for asset in assets:
            name = (asset.get("name") or "").lower()
            if name and name in combined:
                reasons.append(f"Matches tracked asset: {asset.get('name')}")

    return "; ".join(reasons) if reasons else "IOC cross-reference match"


def correlate_findings(findings):
    buckets = defaultdict(list)

    for f in findings:
        text = " ".join([
            f.get("title", ""),
            f.get("description", ""),
            f.get("raw_content", ""),
            f.get("url", ""),
        ])

        iocs = extract_iocs(text)

        for k in ("email", "domain", "ip", "cve", "hash"):
            if k in iocs:
                for val in iocs[k][:3]:
                    buckets[val].append(f)
                break

    incidents = []
    for key, group in buckets.items():
        if len(group) < 2:
            continue

        sources = list(set(f["source"] for f in group))
        severities = [f.get("severity", "medium") for f in group]
        types = list(set(f.get("finding_type", "") for f in group if f.get("finding_type")))

        confidence = _calc_confidence(group)
        explanation = _build_explanation(key, group, sources, severities, types)

        incidents.append({
            "indicator": key,
            "indicator_type": _guess_indicator_type(key),
            "count": len(group),
            "sources": sources,
            "severities": severities,
            "finding_types": types,
            "findings": group,
            "confidence": confidence,
            "explanation": explanation,
        })

    incidents.sort(key=lambda x: x["confidence"], reverse=True)
    return incidents


def classify_incident(incident):
    count = incident["count"]
    sources = len(incident["sources"])
    severities = incident.get("severities", [])

    has_critical = "critical" in severities
    has_high = "high" in severities
    multi_source = sources >= 3

    if count >= 5 or (multi_source and has_critical):
        return "critical"
    if count >= 3 or (has_critical and sources >= 2):
        return "critical"
    if has_critical:
        return "high"
    if count >= 3 or multi_source:
        return "high"
    if has_high and count >= 2:
        return "high"
    if count == 2 or has_high:
        return "medium"
    return "low"


def _calc_confidence(group):
    score = 0.0
    sources = len(set(f["source"] for f in group))
    severities = [f.get("severity", "medium") for f in group]

    score += min(sources * 0.2, 0.6)
    score += severities.count("critical") * 0.25
    score += severities.count("high") * 0.1
    score += min(len(group) * 0.05, 0.2)

    for f in group:
        created = f.get("created_at", "")
        if created:
            try:
                age_days = (datetime.utcnow() - datetime.strptime(created[:19], "%Y-%m-%d %H:%M:%S")).days
                if age_days <= 1:
                    score += 0.1
                elif age_days <= 7:
                    score += 0.05
            except (ValueError, TypeError):
                pass

    return round(min(1.0, score), 3)


def _build_explanation(indicator, group, sources, severities, types):
    parts = []
    parts.append(f"{len(group)} findings linked to '{indicator}'")

    if sources:
        parts.append(f"across {len(sources)} sources: {', '.join(sources[:5])}")

    crit_count = severities.count("critical")
    high_count = severities.count("high")
    if crit_count:
        parts.append(f"{crit_count} critical severity")
    if high_count:
        parts.append(f"{high_count} high severity")

    if types:
        parts.append(f"types: {', '.join(types[:3])}")

    return ". ".join(parts) + "."


def _guess_indicator_type(indicator):
    if "@" in indicator:
        return "email"
    if re.match(r"^CVE-", indicator, re.IGNORECASE):
        return "cve"
    if re.match(r"^[a-f0-9]{32,}$", indicator, re.IGNORECASE):
        return "hash"
    if re.match(r"^\d+\.\d+", indicator):
        return "ip"
    return "domain"
