"""
collectors/cracked.py — cracked.sh / cracked.ax collector.

Platform: cracked.sh (redirects to cracked.ax — MyBB forum)
Strategy: Scan forumdisplay.php?fid=N for thread listings.
         Cookie-based deep-scan of thread content when available.

URL patterns (cracked.ax):
  - Forum listing:      /forumdisplay.php?fid={id}&page=N
  - Thread view:         /Thread-{id}-{slug}
  - Search:              /search.php?action=do_search&keywords=...
  - User profile:        /User-{username}

Auth:
  Set CRACKED_COOKIES in .env.
  Get cookies from browser DevTools after logging into cracked.sh.
  Look for: mybbuser, sid, loginkey cookies.
"""
import hashlib
import logging
import re
import time
import random

from ravencti.collectors.base import job_start, job_done, update_source
from ravencti.config import CRACKED_COOKIES, MONITORED_KEYWORDS, MONITORED_DOMAIN
from ravencti.db.connection import get_db
from ravencti.utils.helpers import severity_from_content, compute_relevance
from ravencti.utils.http import get_session, safe_get

log = logging.getLogger("ravencti.collectors.cracked")

_SOURCE = "cracked"
_BASE_URL = "https://cracked.sh"

_FORUM_FIDS = {
    17: "Cracking",
    18: "Pentesting Help",
    19: "Cracking Tools",
    8: "Lounge",
    10: "LQ Lounge",
    11: "Entertainment",
    15: "Personal",
    4: "Announcements",
    5: "Feedback & Suggestions",
}

_MAX_PAGES = 3
_MAX_THREADS = 200

_RE_THREAD = re.compile(
    r'<a[^>]+href="(Thread-[^"?#]+)"[^>]*>(.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)

_RE_THREAD_FULL = re.compile(
    r'<a[^>]+href="(https?://cracked\.\w+/Thread-[^"?#]+)"[^>]*>(.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)

_RE_AUTHOR = re.compile(
    r'<a[^>]+href="[^"]*"[^>]*class="[^"]*author[^"]*"[^>]*>(.*?)</a>',
    re.DOTALL | re.IGNORECASE,
)

_RE_THREAD_ROW = re.compile(
    r'<tr[^>]*class="[^"]*inline_row[^"]*"[^>]*>.*?</tr>',
    re.DOTALL | re.IGNORECASE,
)

_RE_PREFIX_TAG = re.compile(
    r'<span[^>]*class="[^"]*prefix[^"]*"[^>]*>\s*\[([^\]]*)\]\s*</span>',
    re.IGNORECASE,
)

_RE_CONTENT = re.compile(
    r'class="[^"]*(?:post_content|message|post_body)[^"]*"[^>]*>(.*?)'
    r'(?:</div>\s*){2,}',
    re.DOTALL | re.IGNORECASE,
)

_RE_FID_LINK = re.compile(
    r'href="[^"]*forumdisplay\.php\?fid=(\d+)"',
    re.IGNORECASE,
)


def _apply_cookies(session, cookie_str):
    if not cookie_str:
        return False
    for pair in cookie_str.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, value = pair.split("=", 1)
            session.cookies.set(name.strip(), value.strip())
    return True


def _store(conn, title, description, url, author, raw_content, keyword,
           tags=None, severity=None):
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


def _strip(text):
    if not text:
        return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"&\w+;", "", text)
    return re.sub(r"\s+", " ", text).strip()


def _classify(text):
    tl = text.lower()
    tags = []
    if any(w in tl for w in ["database", "dump", "db leak", "sql dump", "mdb"]):
        tags.append("database")
    if any(w in tl for w in ["credential", "password", "combo", "mail pass"]):
        tags.append("credentials")
    if any(w in tl for w in ["source code", "github", "git", "repo"]):
        tags.append("source_code")
    if any(w in tl for w in ["ransomware", "encrypt", "locked", "ransom"]):
        tags.append("ransomware")
    if any(w in tl for w in ["breach", "leak", "hack", "compromised"]):
        tags.append("breach")
    if any(w in tl for w in ["tool", "crack", "exploit", "0day", "builder"]):
        tags.append("malware_tool")
    return tags


def _extract_threads(html):
    threads = []
    seen = set()

    for row in _RE_THREAD_ROW.finditer(html):
        author_m = _RE_AUTHOR.search(row.group(0))
        for tm in _RE_THREAD.finditer(row.group(0)):
            href = tm.group(1)
            if "?action=" in href or href in seen:
                continue
            title = _strip(tm.group(2))
            if title and len(title) >= 5:
                seen.add(href)
                author = _strip(author_m.group(1)) if author_m else ""
                threads.append({"url": href, "title": title, "author": author})

    if not threads:
        for m in _RE_THREAD_FULL.finditer(html):
            href = m.group(1)
            if "?action=" in href or href in seen:
                continue
            title = _strip(m.group(2))
            if title and len(title) >= 5:
                seen.add(href)
                threads.append({"url": href, "title": title, "author": ""})

    return threads


def _parse_thread_content(html, keyword):
    title = ""
    title_m = re.search(r'<span[^>]*class="[^"]*subject[^"]*"[^>]*>(.*?)</span>', html, re.DOTALL | re.IGNORECASE)
    if title_m:
        title = _strip(title_m.group(1))

    author = ""
    author_m = _RE_AUTHOR.search(html)
    if author_m:
        author = _strip(author_m.group(1))

    content_m = _RE_CONTENT.search(html)
    raw = content_m.group(1) if content_m else ""

    prefix_m = _RE_PREFIX_TAG.search(html)
    prefix = prefix_m.group(1) if prefix_m else ""

    full_text = f"{prefix} {title} {raw}" if prefix else f"{title} {raw}"
    full_text = re.sub(r"\s+", " ", full_text).strip()

    if keyword and keyword.lower() not in full_text.lower():
        return None

    tags = _classify(full_text)
    url_m = re.search(r'href="(Thread-[^"?#]+)"', html, re.IGNORECASE)
    url = url_m.group(1) if url_m else ""

    return {
        "title": f"[Cracked] {prefix} {title}".strip()[:200],
        "description": f"Author: {author or 'unknown'} | Tags: {', '.join(tags) if tags else 'none'}",
        "url": f"{_BASE_URL}/{url}" if url and not url.startswith("http") else (url or ""),
        "author": author,
        "raw_content": full_text[:500],
        "keyword": keyword,
        "tags": tags or None,
    }


def _discover_fids(html):
    fids = []
    for m in _RE_FID_LINK.finditer(html):
        fid = int(m.group(1))
        if fid not in fids:
            fids.append(fid)
    return fids


def collect_cracked():
    jid = job_start("cracked_intel")
    try:
        session = get_session()
        has_cookies = _apply_cookies(session, CRACKED_COOKIES)
        n = 0

        with get_db() as conn:
            threads_seen = set()

            r = safe_get(_BASE_URL, session=session, timeout=25, verify=False)
            if r is not None and r.status_code == 200:
                for fid in _discover_fids(r.text):
                    if fid not in _FORUM_FIDS:
                        _FORUM_FIDS[fid] = f"Forum-{fid}"

            for fid, fname in _FORUM_FIDS.items():
                for page in range(1, _MAX_PAGES + 1):
                    r = safe_get(
                        f"{_BASE_URL}/forumdisplay.php",
                        session=session,
                        params={"fid": fid, "page": page},
                        timeout=25,
                        verify=False,
                    )
                    if r is None or r.status_code != 200:
                        break

                    threads = _extract_threads(r.text)
                    if not threads and page == 1:
                        break

                    for t in threads:
                        if len(threads_seen) >= _MAX_THREADS:
                            break
                        url = t["url"] if t["url"].startswith("http") else f"{_BASE_URL}/{t['url']}"
                        if url in threads_seen:
                            continue
                        threads_seen.add(url)

                        post = {
                            "title": f"[Cracked] {t['title'][:200]}",
                            "description": f"Author: {t['author'] or 'unknown'} | Forum: {fname}",
                            "url": url,
                            "author": t["author"],
                            "raw_content": t["title"],
                            "keyword": "",
                            "tags": _classify(t["title"]) or None,
                        }
                        if _store(conn, **post):
                            n += 1

                    if len(threads_seen) >= _MAX_THREADS:
                        break
                    time.sleep(random.uniform(2, 5))

                if len(threads_seen) >= _MAX_THREADS:
                    break

            for keyword in MONITORED_KEYWORDS:
                try:
                    r = safe_get(
                        f"{_BASE_URL}/search.php",
                        session=session,
                        params={"action": "do_search", "keywords": keyword,
                                "postthread": "1", "showresults": "200"},
                        timeout=25,
                        verify=False,
                    )
                    if r is None or r.status_code != 200:
                        time.sleep(3)
                        continue

                    for t in _extract_threads(r.text):
                        url = t["url"] if t["url"].startswith("http") else f"{_BASE_URL}/{t['url']}"
                        if url in threads_seen:
                            continue
                        threads_seen.add(url)

                        post = {
                            "title": f"[Cracked] {t['title'][:200]}",
                            "description": f"Author: {t['author'] or 'unknown'} | Keyword: {keyword}",
                            "url": url,
                            "author": t["author"],
                            "raw_content": f"{keyword} {t['title']}",
                            "keyword": keyword,
                            "tags": _classify(t["title"]) or None,
                        }
                        if _store(conn, **post):
                            n += 1

                    time.sleep(random.uniform(3, 6))
                except Exception as e:
                    log.debug("[CRACKED] Search error for '%s': %s", keyword, e)
                    time.sleep(5)

            if has_cookies and threads_seen:
                scan_list = list(threads_seen)[:50]
                log.info("[CRACKED] Deep-scanning %d threads with cookies", len(scan_list))
                for url in scan_list:
                    try:
                        full = url if url.startswith("http") else f"{_BASE_URL}/{url}"
                        r = safe_get(full, session=session, timeout=25, verify=False)
                        if r is None or r.status_code != 200:
                            continue

                        post = _parse_thread_content(r.text, None)
                        if post:
                            if _store(conn, **post):
                                n += 1

                        time.sleep(random.uniform(2, 5))
                    except Exception as e:
                        log.debug("[CRACKED] Thread error: %s", e)
                        time.sleep(3)

        update_source("cracked_monitor", "success", n)
        job_done(jid, "completed", n)
        if n > 0:
            log.info("[CRACKED] %d new findings (cookies=%s)", n, has_cookies)
            try:
                from ravencti.services.alerts import run_exposure_alerts
                run_exposure_alerts()
            except Exception:
                pass
        else:
            log.warning("[CRACKED] 0 findings")

    except Exception as e:
        update_source("cracked_monitor", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_cracked failed")
