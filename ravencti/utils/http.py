"""
utils/http.py — Shared HTTP session with retry, backoff, and SSL.

All collectors use get_session() instead of calling requests directly.
This gives us:
  - Automatic retry with exponential backoff (3xx/5xx/network errors)
  - Connection pooling (reuse TCP connections)
  - SSL verification ON by default
  - Consistent proxy + timeout handling
  - Single place to tune HTTP behaviour
"""
import logging
import random
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from ravencti.config import get_proxies

log = logging.getLogger("ravencti.http")

_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
]

_BROWSER_HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "none",
    "Sec-Ch-Ua": '"Chromium";v="131", "Not(A:Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    "Upgrade-Insecure-Requests": "1",
}


def random_ua() -> str:
    return random.choice(_USER_AGENTS)


def _browser_headers():
    h = dict(_BROWSER_HEADERS)
    h["User-Agent"] = random_ua()
    return h


def get_session(extra_headers: dict | None = None) -> requests.Session:
    """
    Return a configured requests.Session with retry + backoff.

    Usage: create once at the start of each collector run and pass it to
    safe_get() / safe_post().  Do NOT share sessions across threads.
    """
    session = requests.Session()

    _RETRY = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )

    adapter = HTTPAdapter(
        max_retries=_RETRY,
        pool_connections=4,
        pool_maxsize=10,
    )
    session.mount("https://", adapter)
    session.mount("http://",  adapter)

    session.headers.update(_browser_headers())
    if extra_headers:
        session.headers.update(extra_headers)

    proxies = get_proxies()
    if proxies is not None:
        session.proxies.update(proxies)

    session.verify = True

    return session


def get_session_json(extra_headers: dict | None = None) -> requests.Session:
    """Session with JSON accept header (for API calls)."""
    h = {"Accept": "application/json"}
    if extra_headers:
        h.update(extra_headers)
    return get_session(h)


def safe_get(url: str, *,
             session: requests.Session | None = None,
             headers: dict | None = None,
             params: dict | None = None,
             timeout: int = 30,
             verify: bool = True) -> requests.Response | None:
    """
    GET with full error handling. Returns Response or None on failure.
    Caller checks response.status_code; exceptions are logged, never raised.
    """
    s = session or get_session()
    try:
        r = s.get(url, headers=headers, params=params, timeout=timeout, verify=verify)
        if r.status_code >= 400:
            log.warning("GET %s → HTTP %d", url[:80], r.status_code)
        return r
    except requests.exceptions.SSLError as e:
        log.warning("SSL error %s: %s — retrying without verify", url[:80], e)
        try:
            return s.get(url, headers=headers, params=params, timeout=timeout, verify=False)
        except Exception as e2:
            log.error("GET %s failed after SSL fallback: %s", url[:80], e2)
            return None
    except requests.exceptions.Timeout:
        log.warning("Timeout: GET %s (>%ds)", url[:80], timeout)
        return None
    except requests.exceptions.ConnectionError as e:
        log.warning("Connection error: GET %s — %s", url[:80], e)
        return None
    except Exception as e:
        log.error("Unexpected error: GET %s — %s", url[:80], e)
        return None


def safe_post(url: str, *,
              session: requests.Session | None = None,
              headers: dict | None = None,
              json: dict | None = None,
              data: dict | None = None,
              timeout: int = 30) -> requests.Response | None:
    """POST with full error handling. Returns Response or None on failure."""
    s = session or get_session()
    try:
        r = s.post(url, headers=headers, json=json, data=data, timeout=timeout)
        if r.status_code >= 400:
            log.warning("POST %s → HTTP %d", url[:80], r.status_code)
        return r
    except requests.exceptions.Timeout:
        log.warning("Timeout: POST %s (>%ds)", url[:80], timeout)
        return None
    except Exception as e:
        log.error("POST %s failed: %s", url[:80], e)
        return None
