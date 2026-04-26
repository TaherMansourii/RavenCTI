"""
utils/helpers.py — Pure utility functions with no side effects.
"""
import hashlib
import json
import re
from datetime import datetime


def safe_str(v, default: str = "") -> str:
    """Coerce v to a stripped string; return default for None or 'none'."""
    if v is None:
        return default
    s = str(v).strip()
    return default if s.lower() == "none" else s


def json_or(v, default):
    """Parse JSON string v; return default on any error."""
    if not v:
        return default
    try:
        return json.loads(v)
    except Exception:
        return default


def now_str() -> str:
    """Current UTC timestamp in SQLite-compatible format."""
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")


def content_hash(*parts: str) -> str:
    """Stable 32-char SHA-256 fingerprint of concatenated strings."""
    combined = ":".join(str(p) for p in parts)
    return hashlib.sha256(combined.encode()).hexdigest()[:32]


def severity_from_content(text: str) -> str:
    """
    Heuristic severity from free text.
    Used by exposure collectors to classify findings.
    """
    tl = text.lower()
    if any(x in tl for x in [
        "password", "passwd", "api_key", "secret_key", "private_key",
        "access_token", "bearer ", "credential", "db dump", "database dump",
        "leaked credentials", ".env", "connection string", "smtp password",
        "-----begin", "aws_secret",
    ]):
        return "critical"
    if any(x in tl for x in [
        "breach", "hack", "compromised", "data leak", "exposed",
        "unauthorized access", "vulnerability", "email list",
        "user list", "employee data", "dump", "leaked", "hacked",
    ]):
        return "high"
    if any(x in tl for x in [
        "mention", "found", "domain", "company", "acquisition",
        "lawsuit", "outage", "incident", "phishing",
    ]):
        return "medium"
    return "low"


# ── Company name normalisation ─────────────────────────────────────────────────
_STOP_SUFFIXES = [
    r"\bInc\.?\b", r"\bLLC\.?\b", r"\bLtd\.?\b", r"\bCorp\.?\b",
    r"\bGroup\b", r"\bHoldings\b", r"\bInternational\b", r"\bGlobal\b",
    r"\bServices?\b", r"\bSolutions?\b", r"\bTechnolog(?:y|ies)\b",
]


def normalise_company(name: str) -> str:
    """
    Strip common corporate suffixes and normalise whitespace.
    Used by client-matching logic.
    """
    s = name.lower().strip()
    s = re.sub(r"[',.\-]", " ", s)
    changed = True
    while changed:
        changed = False
        for pat in _STOP_SUFFIXES:
            new = re.sub(pat, "", s, flags=re.IGNORECASE).strip()
            if new != s:
                s, changed = new, True
    return re.sub(r"\s+", " ", s).strip()


def compute_relevance(title: str, raw_content: str, keywords: list,
                      domain: str = "") -> tuple[int, str]:
    """
    Check if a finding is relevant to the monitored entity.
    Returns (is_relevant: 0|1, match_reason: str).

    The match_reason includes the keyword found and a ~60-char context
    snippet so an analyst can verify relevance at a glance.
    """
    text = f"{title or ''} {raw_content or ''}"
    text_lower = text.lower()

    for kw in keywords:
        kw_lower = kw.lower().strip()
        if not kw_lower:
            continue
        idx = text_lower.find(kw_lower)
        if idx < 0:
            continue
        start = max(0, idx - 30)
        end = min(len(text), idx + len(kw) + 30)
        snippet = text[start:end].replace("\n", " ").strip()
        reason = f"Matched keyword \"{kw}\" in: \"...{snippet}...\""
        return 1, reason

    if domain:
        domain_lower = domain.lower().strip()
        idx = text_lower.find(domain_lower)
        if idx >= 0:
            start = max(0, idx - 30)
            end = min(len(text), idx + len(domain) + 30)
            snippet = text[start:end].replace("\n", " ").strip()
            reason = f"Matched domain \"{domain}\" in: \"...{snippet}...\""
            return 1, reason

    return 0, ""
