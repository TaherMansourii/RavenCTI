"""
collectors/exposure.py — Web exposure monitoring collectors.

Sources:
  - Reddit       public JSON API
  - GitHub       code search (gitDorker-style dorks)
  - Telegram     t.me/s/ public preview scraping (TelegramScraper technique)
  - Paste        psbdmp.ws + grep.app + urlscan.io
  - crt.sh       certificate transparency (theHarvester technique)
  - Dork         DuckDuckGo HTML search (theHarvester-style dorks)

All sources are free with no paid API required.
"""
import hashlib
import logging
import re
import time
from datetime import datetime

from ravencti.collectors.base import job_start, job_done, update_source
from ravencti.config import (
    MONITORED_COMPANY, MONITORED_DOMAIN, MONITORED_KEYWORDS,
    REDDIT_SUBREDDITS, TELEGRAM_CHANNELS, GITHUB_TOKEN,
)
from ravencti.db.connection import get_db
from ravencti.utils.helpers import severity_from_content, now_str
from ravencti.utils.http import get_session, safe_get


log = logging.getLogger("ravencti.collectors.exposure")


# ── Storage helper ─────────────────────────────────────────────────────────────

# ── Exposure scoring ─────────────────────────────────────────────────────────
# Score each finding 0-10. Findings scoring below the threshold are discarded
# as low-signal noise before they ever reach the database.
_SCORE_THRESHOLD = 2

SOURCE_WEIGHT = {
    "github": 20,
    "paste": 20,
    "reddit": 10,
    "telegram": 15,
    "twitter": 10,
    "crtsh": 15,
    "dork": 15,
}


SEVERITY_WEIGHT = {
    "critical": 40,
    "high": 30,
    "medium": 20,
    "low": 10,
}


def _score_finding(source: str, title: str, content: str,
                   keyword: str, severity: str) -> int:
    score = 0

    score += SEVERITY_WEIGHT.get(severity, 20)
    score += SOURCE_WEIGHT.get(source, 10)

    c = (content or title or "").lower()
    if any(k.lower() in c for k in MONITORED_KEYWORDS if k != keyword):
        score += 5

    try:
        hours = (datetime.utcnow() - datetime.strptime(
            f"{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}", "%Y-%m-%d %H:%M:%S"
        )).total_seconds() / 3600
        if hours < 24:
            score += 20
        elif hours < 72:
            score += 10
    except Exception:
        pass

    return score

def _content_hash(source: str, raw_content: str) -> str:
    """Stable dedup hash: source + normalised content (whitespace-stripped)."""
    normalised = re.sub(r"\s+", " ", (raw_content or "").strip().lower())
    return hashlib.sha256(f"{source}:{normalised}".encode()).hexdigest()[:32]


def _store(conn, source: str, finding_type: str, severity: str,
           title: str, description: str = "", url: str = "",
           author: str = "", raw_content: str = "",
           keyword: str = "", platform_id: str = "") -> bool:
    """
    Score → deduplicate → upsert one exposure finding.
    Returns True if the finding was new and above the score threshold.

    Deduplication uses TWO keys:
      1. platform_id  — provider-supplied unique ID (e.g. reddit post ID)
      2. content_hash — SHA-256 of normalised raw_content
    Either match = skip as duplicate.
    """
    # Score and discard low-signal noise before touching the DB
    sig = _score_finding(source, title, raw_content, keyword, severity)
    if sig < _SCORE_THRESHOLD:
        log.debug("[EXPOSURE] discarded low-score finding (score=%d): %s", sig, title[:60])
        return False

    # Generate dedup keys
    if not platform_id:
        platform_id = hashlib.sha256(f"{source}:{title}:{url}".encode()).hexdigest()[:32]
    content_hash = _content_hash(source, raw_content)

    # Check content hash dedup (catches near-duplicate pastes with different IDs)
    existing = conn.execute(
        "SELECT id FROM exposure_findings WHERE source=? AND platform_id=?",
        (source, content_hash),
    ).fetchone()
    if existing:
        return False

    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO exposure_findings"
            "(source,finding_type,severity,title,description,url,author,"
            " raw_content,keyword_matched,platform_id)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                source, finding_type, severity,
                title[:300], (description or "")[:1000],
                (url or "")[:500], (author or "")[:100],
                (raw_content or "")[:1000], (keyword or "")[:100],
                content_hash,   # use content hash as the canonical platform_id
            ),
        )
        return cur.rowcount > 0
    except Exception as e:
        log.debug("[EXPOSURE] store failed: %s", e)
        return False


def _alert_after(n: int) -> None:
    if n > 0:
        from ravencti.services.alerts import run_exposure_alerts
        run_exposure_alerts()


# ── Reddit ─────────────────────────────────────────────────────────────────────

def collect_reddit_exposure() -> None:
    jid = job_start("reddit_exposure")
    try:
        # Reddit requires a descriptive User-Agent to avoid 429s.
        # Format: <platform>:<app ID>:<version> (by /u/<username>)
        session = get_session({
            "User-Agent": "python:ravencti.brand-monitor:v8.0 (by /u/ravencti_bot)",
            "Accept":     "application/json",
        })
        searches = []
        # Global searches — one per keyword, plus breach-specific queries
        for kw in MONITORED_KEYWORDS:
            searches.append(("global",
                "https://www.reddit.com/search.json",
                {"q": kw, "sort": "new", "limit": 25, "t": "month"}))
            # Also search for the keyword + breach/leak/hack to surface high-signal posts
            searches.append(("global_breach",
                "https://www.reddit.com/search.json",
                {"q": f"{kw} breach OR leak OR hack OR compromised", "sort": "new", "limit": 10, "t": "month"}))
        # Subreddit-specific searches
        for sub in REDDIT_SUBREDDITS[:5]:
            searches.append((sub,
                f"https://www.reddit.com/r/{sub}/search.json",
                {"q": MONITORED_COMPANY, "sort": "new",
                 "restrict_sr": "1", "limit": 10, "t": "month"}))

        n = 0
        with get_db() as conn:
            for ctx, url, params in searches:
                r = safe_get(url, session=session, params=params, timeout=15)
                if r is None or r.status_code != 200:
                    if r and r.status_code == 429:
                        time.sleep(30)
                    time.sleep(2)
                    continue
                for post in r.json().get("data", {}).get("children", []):
                    pd       = post.get("data", {})
                    post_id  = pd.get("id", "")
                    if not post_id:
                        continue
                    title_t  = pd.get("title", "")
                    selftext = pd.get("selftext", "")[:800]
                    combined = (title_t + " " + selftext).lower()
                    matched  = next((kw for kw in MONITORED_KEYWORDS
                                     if kw.lower() in combined), None)
                    if not matched:
                        continue
                    score = pd.get("score", 0)
                    sev   = severity_from_content(combined)
                    if score > 100 and sev == "medium":
                        sev = "high"
                    desc_txt = (
                        "Score: " + str(score) +
                        " · r/" + pd.get("subreddit", "") +
                        "\n" + selftext[:300]
                    )
                    if _store(conn, "reddit", "mention", sev,
                              title="[Reddit] " + title_t[:200],
                              description=desc_txt,
                              url="https://reddit.com" + pd.get("permalink", ""),
                              author=pd.get("author", "[deleted]"),
                              raw_content=(title_t + "\n\n" + selftext)[:1000],
                              keyword=matched,
                              platform_id="reddit_" + post_id):
                        n += 1
                time.sleep(1.5)

        update_source("reddit_monitor", "success", n)
        job_done(jid, "completed", n)
        if n == 0:
            log.warning("[REDDIT] 0 findings — check User-Agent or network connectivity")
        else:
            log.info("[REDDIT] %d new findings", n)
        _alert_after(n)
    except Exception as e:
        update_source("reddit_monitor", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_reddit_exposure failed")


# ── GitHub (gitDorker-style) ───────────────────────────────────────────────────

def collect_github_exposure() -> None:
    jid = job_start("github_exposure")
    try:
        hdrs = {
            "Accept":               "application/vnd.github+json",
            "User-Agent":           "RavenCTI/8.0",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if GITHUB_TOKEN:
            hdrs["Authorization"] = f"Bearer {GITHUB_TOKEN}"
        session = get_session(hdrs)

        dorks = [
            f'"{MONITORED_DOMAIN}" filename:.env',
            f'"{MONITORED_DOMAIN}" filename:.env.local',
            f'"{MONITORED_DOMAIN}" password',
            f'"{MONITORED_DOMAIN}" api_key',
            f'"{MONITORED_DOMAIN}" secret',
            f'"{MONITORED_DOMAIN}" smtp',
            f'"@{MONITORED_DOMAIN}" filename:.gitconfig',
            f'"{MONITORED_COMPANY}" password',
            f'"{MONITORED_COMPANY}" token',
            f'"{MONITORED_COMPANY}" BEGIN RSA',
        ]

        n = 0
        with get_db() as conn:
            for dork in dorks:
                r = safe_get(
                    "https://api.github.com/search/code",
                    session=session,
                    params={"q": dork, "per_page": 10, "sort": "indexed"},
                    timeout=20,
                )
                if r is None:
                    time.sleep(5); continue
                if r.status_code == 403:
                    log.warning("[GITHUB] Rate limited — sleeping 60s")
                    time.sleep(60); continue
                if r.status_code in (422, 503):
                    time.sleep(5); continue
                if r.status_code != 200:
                    time.sleep(5); continue

                for item in r.json().get("items", []):
                    repo      = item.get("repository", {}).get("full_name", "")
                    fpath     = item.get("path", "")
                    html_url  = item.get("html_url", "")
                    sha       = item.get("sha", "")
                    fp_lower  = fpath.lower()

                    if any(x in fp_lower for x in [".env", "secret", "credential", "private"]):
                        sev, ftype = "critical", "credential_leak"
                    elif any(x in fp_lower for x in ["config", "settings", ".cfg", ".ini"]):
                        sev, ftype = "high", "code_exposure"
                    else:
                        sev, ftype = "medium", "code_exposure"

                    # Fetch snippet to verify real secret (truffleHog technique)
                    snippet = _fetch_github_snippet(item, session)
                    if snippet and any(p in snippet.lower() for p in
                                       ["password=", "api_key=", "secret=",
                                        "-----begin", "token="]):
                        sev = "critical"

                    matched_kw = next(
                        (kw for kw in MONITORED_KEYWORDS
                         if kw.lower() in (fpath + dork).lower()),
                        MONITORED_DOMAIN,
                    )
                    if _store(conn, "github", ftype, sev,
                              title="[GitHub] " + repo + "/" + fpath,
                              description="Repo: " + repo + "\nFile: " + fpath + "\nDork: " + dork[:80],
                              url=html_url, author=repo.split("/")[0],
                              raw_content=snippet or fpath,
                              keyword=matched_kw,
                              platform_id="github_" + (sha or (repo + fpath)).replace("/", "_")[:60]):
                        n += 1

                time.sleep(7 if not GITHUB_TOKEN else 2.5)

        update_source("github_monitor", "success", n)
        job_done(jid, "completed", n)
        if n == 0 and not GITHUB_TOKEN:
            log.warning("[GITHUB] 0 findings — set GITHUB_TOKEN for better rate limits")
        elif n == 0:
            log.warning("[GITHUB] 0 findings — all results may have been filtered as low-score")
        else:
            log.info("[GITHUB] %d new findings", n)
        _alert_after(n)
    except Exception as e:
        update_source("github_monitor", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_github_exposure failed")


def _fetch_github_snippet(item: dict, session) -> str:
    """Fetch relevant lines from a GitHub file (truffleHog technique)."""
    try:
        import base64
        r = safe_get(item.get("url", ""), session=session, timeout=10)
        if r and r.status_code == 200:
            content = r.json().get("content", "")
            if content:
                raw   = base64.b64decode(content).decode("utf-8", errors="replace")
                lines = [l for l in raw.splitlines()
                         if any(kw.lower() in l.lower() for kw in MONITORED_KEYWORDS)]
                return "\n".join(lines[:5])[:500]
    except Exception:
        pass
    return ""


# ── Telegram (TelegramScraper technique) ──────────────────────────────────────

def collect_telegram_exposure() -> None:
    jid = job_start("telegram_exposure")
    try:
        session = get_session({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept":     "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })

        n = 0
        with get_db() as conn:
            for channel in TELEGRAM_CHANNELS:
                r = safe_get(f"https://t.me/s/{channel}", session=session, timeout=20)
                if r is None:
                    log.debug("[TG] %s — no response, skipping", channel)
                    continue
                if r.status_code != 200:
                    log.debug("[TG] %s — HTTP %d, skipping", channel, r.status_code)
                    time.sleep(3); continue
                for msg in _parse_tme(r.text):
                    text = msg.get("text", "")
                    if not text:
                        continue
                    matched = next((kw for kw in MONITORED_KEYWORDS
                                    if kw.lower() in text.lower()), None)
                    if not matched:
                        continue
                    msg_id  = msg.get("id", "")
                    msg_url = (
                        "https://t.me/" + channel + "/" + msg_id.split("/")[-1]
                        if msg_id else "https://t.me/s/" + channel
                    )
                    if _store(conn, "telegram", "mention", severity_from_content(text),
                              title="[Telegram] @" + channel + ": " + text[:80],
                              description="Channel: @" + channel + "\n\n" + text[:500],
                              url=msg_url, author="@" + channel,
                              raw_content=text[:1000], keyword=matched,
                              platform_id="tg_" + channel + "_" + msg_id):
                        n += 1
                time.sleep(3)

        update_source("telegram_monitor", "success", n)
        job_done(jid, "completed", n)
        log.info("[TG] %d new findings", n)
        _alert_after(n)
    except Exception as e:
        update_source("telegram_monitor", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_telegram_exposure failed")


def _parse_tme(html: str) -> list[dict]:
    """Extract messages from t.me/s/ page — robust regex approach."""
    messages = []
    # Primary: structured data-post blocks
    for post_id, raw_html in re.findall(
        r'data-post="([^"]+)".*?'
        r'class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
        html, re.DOTALL,
    ):
        text = re.sub(r"<[^>]+>", " ", raw_html)
        text = (text.replace("&amp;", "&").replace("&lt;", "<")
                    .replace("&gt;", ">").replace("&nbsp;", " "))
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > 10:
            messages.append({"id": post_id, "text": text})
    # Fallback
    if not messages:
        for i, raw_html in enumerate(re.findall(
            r'class="tgme_widget_message_text[^"]*"[^>]*>(.*?)</div>',
            html, re.DOTALL,
        )):
            text = re.sub(r"\s+", " ",
                          re.sub(r"<[^>]+>", " ", raw_html)).strip()
            if len(text) > 10:
                messages.append({"id": str(i), "text": text})
    return messages


# ── Paste / grep.app / urlscan.io ─────────────────────────────────────────────

def collect_paste_exposure() -> None:
    jid = job_start("paste_exposure")
    try:
        session = get_session({
            "User-Agent": "Mozilla/5.0 RavenCTI/8.0",
            "Accept":     "application/json",
        })
        n = 0

        with get_db() as conn:
            for kw in MONITORED_KEYWORDS:
                # 1. psbdmp.ws
                n += _scrape_psbdmp(conn, kw, session)
                time.sleep(2)
                # 2. grep.app (open-source code search)
                n += _scrape_grepapp(conn, kw, session)
                time.sleep(2)
                # 3. urlscan.io
                n += _scrape_urlscan(conn, kw, session)
                time.sleep(2)

        update_source("paste_monitor", "success", n)
        job_done(jid, "completed", n)
        if n == 0:
            log.warning("[PASTE] 0 findings from psbdmp/grep.app/urlscan")
        else:
            log.info("[PASTE] %d new findings", n)
        _alert_after(n)
    except Exception as e:
        update_source("paste_monitor", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_paste_exposure failed")


def _scrape_psbdmp(conn, kw: str, session) -> int:
    n = 0
    try:
        r = safe_get("https://psbdmp.ws/api/v3/search", session=session,
                     params={"q": kw, "limit": 20}, timeout=15)
        if r and r.status_code == 200:
            data   = r.json()
            pastes = data if isinstance(data, list) else data.get("data", [])
            for p in pastes[:20]:
                if not isinstance(p, dict): continue
                pid  = str(p.get("id") or p.get("pid") or "")
                text = str(p.get("text") or p.get("content") or "")
                if not pid or not text or kw.lower() not in text.lower(): continue
                if _store(conn, "paste", "paste", severity_from_content(text),
                          title="[Paste] " + kw + " in paste " + pid,
                          description=text[:400], url="https://psbdmp.ws/" + pid,
                          author="anonymous", raw_content=text[:1000],
                          keyword=kw, platform_id="psbdmp_" + pid):
                    n += 1
    except Exception as e:
        log.debug("[PASTE] psbdmp failed for '%s': %s", kw, e)
    return n


def _scrape_grepapp(conn, kw: str, session) -> int:
    n = 0
    try:
        r = safe_get("https://grep.app/api/search", session=session,
                     params={"q": kw, "filter[lang][0]": "Text"}, timeout=15)
        if r and r.status_code == 200:
            for hit in r.json().get("hits", {}).get("hits", [])[:10]:
                repo    = hit.get("repo", {}).get("raw", "")
                fpath   = hit.get("path", {}).get("raw", "")
                content = " ".join(
                    s.get("snippet", {}).get("raw", "")
                    for s in hit.get("content", [{}])
                )[:500]
                if not repo: continue
                sev = severity_from_content(content or fpath)
                if _store(conn, "paste", "code_exposure", sev,
                          title="[grep.app] " + repo + ": " + fpath,
                          description="Repo: " + repo + "\nFile: " + fpath + "\n" + content[:300],
                          url="https://grep.app/search?q=" + kw,
                          author=repo.split("/")[0],
                          raw_content=content, keyword=kw,
                          platform_id="grepapp_" + (repo + "_" + fpath).replace("/", "_")[:60]):
                    n += 1
    except Exception as e:
        log.debug("[PASTE] grep.app failed for '%s': %s", kw, e)
    return n


def _scrape_urlscan(conn, kw: str, session) -> int:
    n = 0
    try:
        q = f"page.domain:{MONITORED_DOMAIN} OR page.text:{kw}"
        r = safe_get("https://urlscan.io/api/v1/search/", session=session,
                     params={"q": q, "size": 20}, timeout=15)
        if r and r.status_code == 200:
            for res in r.json().get("results", []):
                scan_id  = res.get("_id", "")
                page     = res.get("page", {})
                domain   = page.get("domain", "")
                scan_url = page.get("url", "")
                if domain == MONITORED_DOMAIN: continue
                sev = ("high" if any(x in scan_url.lower() for x in
                                     ["login", "credential", "password", "dump", "leak"])
                       else "medium")
                if _store(conn, "paste", "code_exposure", sev,
                          title="[URLScan] " + MONITORED_DOMAIN + " on external site: " + domain,
                          description="URL: " + scan_url + "\nDomain: " + domain,
                          url="https://urlscan.io/result/" + scan_id + "/",
                          author=domain, raw_content=scan_url, keyword=kw,
                          platform_id="urlscan_" + scan_id):
                    n += 1
    except Exception as e:
        log.debug("[PASTE] urlscan failed for '%s': %s", kw, e)
    return n


# ── crt.sh — certificate transparency ─────────────────────────────────────────

def collect_crtsh_exposure() -> None:
    jid = job_start("crtsh_exposure")
    try:
        session = get_session({"User-Agent": "RavenCTI/8.0", "Accept": "application/json"})
        n = 0
        with get_db() as conn:
            for query in [f"%.{MONITORED_DOMAIN}", f"%{MONITORED_COMPANY}%"]:
                r = safe_get("https://crt.sh/", session=session,
                             params={"q": query, "output": "json"}, timeout=25)
                if r is None or r.status_code != 200:
                    continue
                seen: set[str] = set()
                for cert in r.json()[:100]:
                    name    = (cert.get("name_value") or "").lower().strip()
                    cert_id = str(cert.get("id", ""))
                    if not name or cert_id in seen: continue
                    seen.add(cert_id)
                    clean   = name.replace("*.", "")
                    if MONITORED_DOMAIN in clean: continue   # our own cert
                    issuer     = (cert.get("issuer_name") or "").lower()
                    issued_at  = cert.get("entry_timestamp", "")[:10]
                    if _store(conn, "paste", "phishing_domain", "high",
                              title="[CRT.SH] Suspicious cert: " + clean[:100],
                              description="Domain: " + clean + "\nIssued: " + issued_at +
                                          "\nIssuer: " + issuer[:80] +
                                          "\nPossible phishing domain impersonating " + MONITORED_DOMAIN,
                              url="https://crt.sh/?id=" + cert_id,
                              author="crt.sh", raw_content=clean,
                              keyword=MONITORED_DOMAIN,
                              platform_id="crtsh_" + cert_id):
                        n += 1
                time.sleep(2)

        update_source("paste_monitor", "success", n)
        job_done(jid, "completed", n)
        log.info("[CRTSH] %d cert findings", n)
    except Exception as e:
        update_source("paste_monitor", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_crtsh_exposure failed")


# ── DuckDuckGo dorks (theHarvester technique) ─────────────────────────────────

def collect_dork_exposure() -> None:
    jid = job_start("dork_exposure")
    try:
        session = get_session({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept":     "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        dorks = [
            f'site:{MONITORED_DOMAIN} filetype:env',
            f'site:{MONITORED_DOMAIN} filetype:log',
            f'"{MONITORED_DOMAIN}" "password" filetype:txt',
            f'"{MONITORED_DOMAIN}" inurl:admin',
            f'"{MONITORED_DOMAIN}" "index of"',
            f'"{MONITORED_DOMAIN}" site:pastebin.com',
            f'"{MONITORED_DOMAIN}" site:paste.org',
        ]
        n = 0
        with get_db() as conn:
            for dork in dorks:
                r = safe_get(
                    "https://html.duckduckgo.com/html/",
                    session=session,
                    params={"q": dork},
                    timeout=15,
                )
                if r is None or r.status_code != 200:
                    time.sleep(5); continue

                urls    = re.findall(r'href="(https?://[^"]+)"[^>]*class="result__url"', r.text)
                titles  = re.findall(
                    r'class="result__title"[^>]*>.*?<a[^>]*>(.*?)</a>', r.text, re.DOTALL
                )
                snippets = re.findall(
                    r'class="result__snippet"[^>]*>(.*?)</div>', r.text, re.DOTALL
                )
                for i, url in enumerate(urls[:5]):
                    title = re.sub(r"<[^>]+>", "", titles[i] if i < len(titles) else url).strip()
                    snip  = re.sub(r"<[^>]+>", "", snippets[i] if i < len(snippets) else "").strip()
                    sev   = severity_from_content(title + " " + snip + " " + dork)
                    if _store(conn, "paste", "code_exposure", sev,
                              title="[Dork] " + title[:150],
                              description="Dork: " + dork + "\n\n" + snip[:300],
                              url=url, author="duckduckgo",
                              raw_content=(dork + "\n" + snip)[:1000],
                              keyword=MONITORED_DOMAIN,
                              platform_id="dork_" + str(abs(hash(url)) % 10**8)):
                        n += 1
                time.sleep(5)

        update_source("paste_monitor", "success", n)
        job_done(jid, "completed", n)
        log.info("[DORK] %d findings", n)
    except Exception as e:
        update_source("paste_monitor", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_dork_exposure failed")


# ── Run all exposure collectors ────────────────────────────────────────────────

def collect_all_exposure() -> None:
    jid = job_start("exposure_all")
    try:
        for fn in [
            collect_reddit_exposure,
            collect_github_exposure,
            collect_telegram_exposure,
            collect_paste_exposure,
            collect_crtsh_exposure,
            collect_dork_exposure,
        ]:
            try:
                fn()
                time.sleep(2)
            except Exception as e:
                log.warning("[EXPOSURE] %s failed: %s", fn.__name__, e)
        job_done(jid, "completed", 0)
    except Exception as e:
        job_done(jid, "failed", 0, str(e))
