"""
collectors/darkforums.py — darkforums.su collector.

Platform: darkforums.su (WAF-protected, likely Cloudflare)
Strategy: Cookie-based authenticated requests.
Fallback: If cookies unavailable, attempt unauthenticated scrape
         (will likely get 403 — user must configure DARKFORUMS_COOKIES).

Data extraction:
  - Thread listings from search and forum pages
  - Individual thread content
  - Tags: database, credentials, source_code, ransomware, breach

Auth:
  Set DARKFORUMS_COOKIES in .env or environment.
  Get cookies from browser DevTools > Application > Cookies after login.
"""
import hashlib
import logging
import re
import time
import random

from ravencti.collectors.base import job_start, job_done, update_source
from ravencti.config import DARKFORUMS_COOKIES, MONITORED_KEYWORDS, MONITORED_DOMAIN
from ravencti.db.connection import get_db
from ravencti.utils.helpers import severity_from_content, compute_relevance
from ravencti.utils.http import get_session, safe_get

log = logging.getLogger("ravencti.collectors.darkforums")

_SOURCE = "darkforums"
_BASE_URL = "https://darkforums.su"

_PATHS_TO_SCAN = [
    "/",
    "/threads",
    "/search",
    "/forum/leaks-databases.4/",
    "/forum/cracking-tools.5/",
    "/forum/combo-lists.6/",
    "/forum/credentials-dumps.7/",
]

_MYBB_THREAD_RE = re.compile(
    r'<a[^>]+href="(/threads/[^"]+)"[^>]*>'
    r'[^<]*<span[^>]*class="[^"]*subject[^"]*"[^>]*>(.*?)</span>',
    re.DOTALL | re.IGNORECASE,
)

_MYBB_AUTHOR_RE = re.compile(
    r'<a[^>]+href="[^"]*"[^>]*class="[^"]*author[^"]*"[^>]*>(.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)

_MYBB_DATETIME_RE = re.compile(
    r'<span[^>]*class="[^"]*(?:date|time|start|lastpost)[^"]*"[^>]*>(.*?)</span>',
    re.DOTALL | re.IGNORECASE,
)

_THREADED_REPLY_RE = re.compile(
    r'class="[^"]*thread_title[^"]*"[^>]*>\s*<a[^>]+href="(/threads/[^"]+)"[^>]*>(.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)

_GENERIC_THREAD_LINK_RE = re.compile(
    r'href="(/threads/[^"?#]+)',
    re.IGNORECASE,
)


def _apply_cookies(session, cookie_str: str):
    if not cookie_str:
        return False
    for pair in cookie_str.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, value = pair.split("=", 1)
            session.cookies.set(name.strip(), value.strip())
    return True


def _store(conn, title, description, url, author, raw_content, keyword,
           tags=None, severity=None, post_date=None):
    norm = re.sub(r"\s+", " ", (raw_content or title or "").strip().lower())
    if len(norm) < 5:
        return False
    pid = hashlib.sha256(f"{_SOURCE}:{norm}".encode()).hexdigest()[:32]

    existing = conn.execute(
        "SELECT id FROM exposure_findings WHERE source=? AND platform_id=?",
        (_SOURCE, pid),
    ).fetchone()
    if existing:
        return False

    sev = severity or severity_from_content(raw_content or title)
    is_relevant, match_reason = compute_relevance(
        title, raw_content, MONITORED_KEYWORDS, MONITORED_DOMAIN)

    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO exposure_findings"
            "(source,finding_type,severity,title,description,url,author,"
            " raw_content,keyword_matched,platform_id,is_relevant,match_reason)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (_SOURCE, "darkweb_post", sev,
             title[:300], (description or "")[:1000],
             (url or "")[:500], (author or "")[:100],
             (raw_content or "")[:1000], (keyword or "")[:100],
             pid, is_relevant, match_reason),
        )
        return cur.rowcount > 0
    except Exception as e:
        log.debug("[%s] Store failed: %s", _SOURCE.upper(), e)
        return False


def _strip_html(text):
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&amp;", "&", text)
    text = re.sub(r"&lt;", "<", text)
    text = re.sub(r"&gt;", ">", text)
    text = re.sub(r"&quot;", '"', text)
    text = re.sub(r"&#?\w+;", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _classify_tags(text):
    tl = text.lower()
    tags = []
    if any(w in tl for w in ["database", "dump", "db leak", "sql dump", "mdb"]):
        tags.append("database")
    if any(w in tl for w in ["credential", "password", "login", "combo", "mail pass"]):
        tags.append("credentials")
    if any(w in tl for w in ["source code", "github", "git", "repo"]):
        tags.append("source_code")
    if any(w in tl for w in ["ransomware", "encrypt", "locked", "ransom"]):
        tags.append("ransomware")
    if any(w in tl for w in ["breach", "leak", "hack", "compromised"]):
        tags.append("breach")
    return tags


def _parse_thread_links(html):
    links = []
    seen = set()
    for match in _GENERIC_THREAD_LINK_RE.finditer(html):
        href = match.group(1).split("?")[0].split("#")[0]
        if href in seen:
            continue
        seen.add(href)
        links.append(href)
    return links


def _parse_listing_page(html, keyword):
    posts = []
    threads = _MYBB_THREAD_RE.findall(html)

    if not threads:
        threads = _THREADED_REPLY_RE.findall(html)

    seen = set()
    for href_match, title_raw in threads:
        title = _strip_html(title_raw)
        if not title or len(title) < 5 or title in seen:
            continue
        seen.add(title)

        if keyword and keyword.lower() not in title.lower():
            continue

        author_match = _MYBB_AUTHOR_RE.search(html)
        author = _strip_html(author_match.group(1)) if author_match else ""

        tags = _classify_tags(title)
        full_url = href_match if href_match.startswith("http") else f"{_BASE_URL}{href_match}"

        posts.append({
            "title": f"[DarkForums] {title[:200]}",
            "description": f"Author: {author or 'unknown'} | Tags: {', '.join(tags) if tags else 'none'}",
            "url": full_url,
            "author": author,
            "raw_content": title,
            "keyword": keyword,
            "tags": tags or None,
        })

    return posts


def _scrape_forum_page(session, path, keyword):
    r = safe_get(f"{_BASE_URL}{path}", session=session, timeout=25)
    if r is None or r.status_code != 200:
        return []

    posts = _parse_listing_page(r.text, keyword)

    if not posts and not keyword:
        posts = _parse_listing_page(r.text, None)

    return posts


def collect_darkforums():
    jid = job_start("darkforums_intel")
    try:
        session = get_session()
        has_cookies = _apply_cookies(session, DARKFORUMS_COOKIES)

        if not has_cookies:
            log.warning("[DARKFORUMS] No cookies configured — unauthenticated scrape will likely fail")

        n = 0
        with get_db() as conn:
            for path in _PATHS_TO_SCAN:
                try:
                    posts = _scrape_forum_page(session, path, None)
                    for post in posts:
                        if _store(conn, **post):
                            n += 1
                    time.sleep(random.uniform(2, 5))
                except Exception as e:
                    log.debug("[DARKFORUMS] Error on %s: %s", path, e)
                    time.sleep(3)

            for keyword in MONITORED_KEYWORDS:
                try:
                    r = safe_get(
                        f"{_BASE_URL}/search",
                        session=session,
                        params={"keywords": keyword, "action": "do_search", " forums": "all"},
                        timeout=25,
                    )
                    if r is None or r.status_code != 200:
                        time.sleep(3)
                        continue

                    posts = _parse_listing_page(r.text, keyword)
                    for post in posts:
                        if _store(conn, **post):
                            n += 1

                    time.sleep(random.uniform(3, 6))
                except Exception as e:
                    log.debug("[DARKFORUMS] Search error for '%s': %s", keyword, e)
                    time.sleep(5)

        update_source("darkforums_monitor", "success", n)
        job_done(jid, "completed", n)
        if n > 0:
            log.info("[DARKFORUMS] %d new findings (cookies=%s)", n, has_cookies)
            try:
                from ravencti.services.alerts import run_exposure_alerts
                run_exposure_alerts()
            except Exception:
                pass
        else:
            log.warning("[DARKFORUMS] 0 findings")

    except Exception as e:
        update_source("darkforums_monitor", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_darkforums failed")
