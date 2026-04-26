"""
collectors/darkweb.py — Dark web intelligence collectors.

Sources:
  darkforums.su  — Forum scraping for monitored entity mentions
  patched.to     — Forum scraping for monitored entity mentions
  cracked.ax     — Forum scraping for monitored entity mentions
"""
import logging
import time

from ravencti.collectors.darkforums import collect_darkforums
from ravencti.collectors.patched import collect_patched
from ravencti.collectors.cracked import collect_cracked

log = logging.getLogger("ravencti.collectors.darkweb")


def collect_all_darkweb() -> None:
    from ravencti.collectors.base import job_start, job_done
    jid = job_start("darkweb_all")
    try:
        for fn in [collect_darkforums, collect_patched, collect_cracked]:
            try:
                fn()
                time.sleep(2)
            except Exception as e:
                log.warning("[DARKWEB] %s failed: %s", fn.__name__, e)
        job_done(jid, "completed", 0)
    except Exception as e:
        job_done(jid, "failed", 0, str(e))
