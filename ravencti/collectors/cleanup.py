"""
collectors/cleanup.py — Purge stale data that no longer has operational value.
"""
import logging

from ravencti.collectors.base import job_start, job_done
from ravencti.config import IOC_MAX_AGE_DAYS
from ravencti.db.connection import get_db

log = logging.getLogger("ravencti.collectors.cleanup")


def cleanup_stale_data() -> None:
    jid = job_start("data_cleanup")
    try:
        with get_db() as conn:
            r1 = conn.execute(
                f"DELETE FROM iocs WHERE first_seen < datetime('now','-{IOC_MAX_AGE_DAYS} days')"
            )
            r2 = conn.execute(
                "DELETE FROM alerts WHERE status='resolved' "
                "AND created_at < datetime('now','-30 days')"
            )
            r3 = conn.execute(
                "DELETE FROM collection_jobs WHERE started_at < datetime('now','-14 days')"
            )
            r4 = conn.execute(
                "DELETE FROM exposure_findings "
                "WHERE status IN ('resolved','false_positive') "
                "AND created_at < datetime('now','-60 days')"
            )
            total = r1.rowcount + r2.rowcount + r3.rowcount + r4.rowcount

        log.info(
            "[CLEANUP] Purged: %d stale IOCs, %d old alerts, "
            "%d job logs, %d old exposure findings",
            r1.rowcount, r2.rowcount, r3.rowcount, r4.rowcount,
        )
        job_done(jid, "completed", total)
    except Exception as e:
        job_done(jid, "failed", 0, str(e))
        log.exception("cleanup_stale_data failed")
