"""
config.py — Central configuration for RavenCTI.
All values read from environment variables.
Copy .env.example to .env and fill in your keys.
"""
import os
import secrets
from pathlib import Path

# ── Paths (defined first so load_dotenv can find .env) ────────────────────────
VERSION = "8.0"
BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
LOG_DIR  = BASE_DIR / "logs"
DB_PATH  = DATA_DIR / "ravencti.db"

DATA_DIR.mkdir(exist_ok=True)
LOG_DIR.mkdir(exist_ok=True)

# ── Load .env BEFORE reading any env vars ─────────────────────────────────────
# Tries ravencti/.env first, then searches upward from cwd.
try:
    from dotenv import load_dotenv
    _env = BASE_DIR / ".env"
    load_dotenv(dotenv_path=_env if _env.exists() else None, override=False)
except ImportError:
    pass  # python-dotenv not installed; env vars must come from the shell

# ── Flask ──────────────────────────────────────────────────────────────────────
# FLASK_SECRET_KEY is required at runtime. We fall back to a random value so
# that module imports never crash — app.py logs a warning if it was not set.
FLASK_SECRET_KEY = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
API_KEY          = os.environ.get("API_KEY", "")   # x-api-key header; empty = disabled

# ── External API Keys ──────────────────────────────────────────────────────────
NVD_API_KEY  = os.environ.get("NVD_API_KEY",  "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")

# ── Target Identity ────────────────────────────────────────────────────────────
MONITORED_COMPANY  = os.environ.get("MONITORED_COMPANY",  "soprahr")
MONITORED_DOMAIN   = os.environ.get("MONITORED_DOMAIN",   "soprahr.com")
MONITORED_KEYWORDS = [
    k.strip()
    for k in os.environ.get("MONITORED_KEYWORDS", "soprahr,soprahr.com").split(",")
    if k.strip()
]

# ── Exposure Sources ───────────────────────────────────────────────────────────
REDDIT_SUBREDDITS = [
    "cybersecurity", "netsec", "hacking", "DataBreaches",
    "privacy", "darkweb", "leaks", "Malware", "AskNetsec",
]
TELEGRAM_CHANNELS = [
    "breachdetector", "databreaches", "cybersecuritynews",
    "cthfeed", "databreaches_feed", "leakcheck_io",
]

# ── API URLs ───────────────────────────────────────────────────────────────────
NVD_URL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL         = "https://api.first.org/data/v1/epss"
RANSOMWARE_URLS  = [
    "https://api.ransomware.live/v2/recentvictims",
    "https://api.ransomware.live/recentvictims",
    "https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json",
]
MITRE_ATTACK_URLS = [
    "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json",
]

# ── CTI Tuning ─────────────────────────────────────────────────────────────────
CVE_MIN_CVSS          = float(os.environ.get("CVE_MIN_CVSS",          "6.0"))
CVE_MIN_YEAR          = int(os.environ.get("CVE_MIN_YEAR",            "2019"))
CVE_AI_SKIP_THRESHOLD = float(os.environ.get("CVE_AI_SKIP_THRESHOLD", "4.0"))
IOC_MAX_AGE_DAYS      = int(os.environ.get("IOC_MAX_AGE_DAYS",        "14"))
ALERT_DEDUP_HOURS     = int(os.environ.get("ALERT_DEDUP_HOURS",       "24"))

# ── Proxy ──────────────────────────────────────────────────────────────────────
CTI_PROXY    = os.environ.get("CTI_PROXY", "")
NO_CTI_PROXY = os.environ.get("NO_CTI_PROXY", "0") == "1"

def get_proxies() -> dict | None:
    if NO_CTI_PROXY:
        return {"http": "", "https": ""}
    if CTI_PROXY:
        return {"http": CTI_PROXY, "https": CTI_PROXY}
    return None

# ── Auth / JWT ───────────────────────────────────────────────────────────────────
JWT_SECRET        = os.environ.get("JWT_SECRET", FLASK_SECRET_KEY)
JWT_EXPIRATION_H  = int(os.environ.get("JWT_EXPIRATION_H", "24"))
JWT_ALGORITHM     = "HS256"
AUTH_ENABLED      = os.environ.get("AUTH_ENABLED", "1") == "1"
DEFAULT_ADMIN_PW  = os.environ.get("DEFAULT_ADMIN_PW", "admin")

# ── Dark Web Forum Cookies ─────────────────────────────────────────────────────
# Paste your browser cookies from each forum after logging in.
# Format: "key1=value1; key2=value2"
DARKFORUMS_COOKIES = os.environ.get("DARKFORUMS_COOKIES", "")
PATCHED_COOKIES    = os.environ.get("PATCHED_COOKIES", "")
CRACKED_COOKIES    = os.environ.get("CRACKED_COOKIES", "")

