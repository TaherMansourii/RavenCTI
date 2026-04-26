"""
collectors/twitter.py — X/Twitter OSINT collector.

Monitors X (Twitter) for mentions of monitored entities via Nitter instances
and public search endpoints.

Schema normalization:
  - title: tweet text
  - date: tweet date
  - author: @handle
  - source: "twitter"
  - normalized to exposure_findings table
"""
import hashlib
import logging
import re
import time

from ravencti.collectors.base import job_start, job_done, update_source
from ravencti.config import MONITORED_COMPANY, MONITORED_DOMAIN, MONITORED_KEYWORDS
from ravencti.db.connection import get_db
from ravencti.utils.helpers import severity_from_content
from ravencti.utils.http import get_session, safe_get

log = logging.getLogger("ravencti.collectors.twitter")

_SOURCE = "twitter"
_NITTER_INSTANCES = [
    "https://nitter.privacydev.net",
    "https://nitter.poast.org",
]


def _store(conn, title, description, url, author, raw_content, keyword, severity=None):
    norm = re.sub(r"\s+", " ", (raw_content or title or "").strip().lower())
    pid = hashlib.sha256(f"{_SOURCE}:{norm}".encode()).hexdigest()[:32]

    existing = conn.execute(
        "SELECT id FROM exposure_findings WHERE source=? AND platform_id=?",
        (_SOURCE, pid),
    ).fetchone()
    if existing:
        return False

    sev = severity or severity_from_content(raw_content or title)

    try:
        cur = conn.execute(
            "INSERT OR IGNORE INTO exposure_findings"
            "(source,finding_type,severity,title,description,url,author,"
            " raw_content,keyword_matched,platform_id)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (_SOURCE, "social_mention", sev,
             title[:300], (description or "")[:1000],
             (url or "")[:500], (author or "")[:100],
             (raw_content or "")[:1000], (keyword or "")[:100],
             pid),
        )
        return cur.rowcount > 0
    except Exception as e:
        log.debug("[%s] Store failed: %s", _SOURCE.upper(), e)
        return False


def collect_twitter() -> None:
    jid = job_start("twitter_exposure")
    try:
        session = get_session({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
        })
        n = 0

        with get_db() as conn:
            for keyword in MONITORED_KEYWORDS:
                found = False
                for instance in _NITTER_INSTANCES:
                    try:
                        r = safe_get(
                            f"{instance}/search",
                            session=session,
                            params={"f": "tweets", "q": keyword},
                            timeout=15,
                        )
                        if r is None or r.status_code != 200:
                            time.sleep(2)
                            continue

                        tweets = _parse_nitter(r.text, keyword)
                        for tweet in tweets:
                            if _store(conn, **tweet):
                                n += 1
                        if tweets:
                            found = True
                        time.sleep(3)
                        break
                    except Exception:
                        time.sleep(3)
                        continue

                if not found:
                    try:
                        r = safe_get(
                            "https://html.duckduckgo.com/html/",
                            session=session,
                            params={"q": f"site:x.com {keyword}"},
                            timeout=15,
                        )
                        if r and r.status_code == 200:
                            tweets = _parse_duckduckgo(r.text, keyword)
                            for tweet in tweets:
                                if _store(conn, **tweet):
                                    n += 1
                    except Exception:
                        pass
                time.sleep(2)

        update_source("twitter_monitor", "success", n)
        job_done(jid, "completed", n)
        if n > 0:
            log.info("[TWITTER] %d new findings", n)
            try:
                from ravencti.services.alerts import run_exposure_alerts
                run_exposure_alerts()
            except Exception:
                pass
        else:
            log.warning("[TWITTER] 0 findings")
    except Exception as e:
        update_source("twitter_monitor", "error")
        job_done(jid, "failed", 0, str(e))
        log.exception("collect_twitter failed")


def _parse_nitter(html, keyword):
    tweets = []
    blocks = re.findall(
        r'<div class="timeline-item"[^>]*>.*?'
        r'<a[^>]*class="tweet-link"[^>]*href="([^"]*)"[^>]*>.*?'
        r'class="tweet-content[^"]*"[^>]*>(.*?)</div>.*?'
        r'class="tweet-name"[^>]*>(.*?)</a>',
        html, re.DOTALL | re.IGNORECASE,
    )
    seen = set()
    for href, content_raw, author_raw in blocks:
        content = re.sub(r"<[^>]+>", " ", content_raw).strip()
        author = re.sub(r"<[^>]+>", "", author_raw).strip()
        if not content or len(content) < 10 or content in seen:
            continue
        seen.add(content)
        kl = keyword.lower()
        if kl not in content.lower():
            continue
        tweets.append({
            "title": f"[X] {content[:200]}",
            "description": f"Author: @{author if author else 'unknown'}",
            "url": href if href.startswith("http") else f"https://x.com{href}",
            "author": f"@{author}" if author else "",
            "raw_content": f"{keyword} {content}",
            "keyword": keyword,
        })

    if not tweets:
        text_blocks = re.findall(
            r'class="tweet-content[^"]*"[^>]*>(.*?)</div>',
            html, re.DOTALL | re.IGNORECASE,
        )
        for tb in text_blocks[:20]:
            text = re.sub(r"<[^>]+>", " ", tb).strip()
            if len(text) > 10 and kl in text.lower() and text not in seen:
                seen.add(text)
                tweets.append({
                    "title": f"[X] {text[:200]}",
                    "description": "Source: X (Twitter)",
                    "url": "https://x.com",
                    "author": "",
                    "raw_content": f"{keyword} {text}",
                    "keyword": keyword,
                })

    return tweets[:15]


def _parse_duckduckgo(html, keyword):
    tweets = []
    urls = re.findall(
        r'href="(https?://x\.com/[^"]+)"',
        html, re.IGNORECASE,
    )
    titles = re.findall(
        r'class="result__title"[^>]*>.*?<a[^>]*>(.*?)</a>',
        html, re.DOTALL | re.IGNORECASE,
    )
    snippets = re.findall(
        r'class="result__snippet"[^>]*>(.*?)</div>',
        html, re.DOTALL | re.IGNORECASE,
    )
    for i, url in enumerate(urls[:10]):
        title = re.sub(r"<[^>]+>", "", titles[i] if i < len(titles) else url).strip()
        snip = re.sub(r"<[^>]+>", "", snippets[i] if i < len(snippets) else "").strip()
        if not title:
            continue
        tweets.append({
            "title": f"[X] {title[:200]}",
            "description": f"URL: {url}\n{snip[:200]}",
            "url": url,
            "author": "",
            "raw_content": f"{keyword} {title} {snip}",
            "keyword": keyword,
        })
    return tweets
