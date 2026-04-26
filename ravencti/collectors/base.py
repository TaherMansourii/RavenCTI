"""
collectors/base.py — Shared scaffolding for all collectors.

Every collector follows the same pattern:
  jid = job_start("job_name")
  try:
      ... collect data ...
      job_done(jid, "completed", count)
      update_source("source_name", "success", count)
  except Exception as e:
      job_done(jid, "failed", 0, str(e))
      update_source("source_name", "error")
      log.exception(...)

BaseCollector provides a standardised interface for future migration
to async or plugin-based collectors.
"""
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ravencti.db.connection import get_db
from ravencti.db.schema import update_source as _update_source
from ravencti.utils.helpers import now_str

log = logging.getLogger("ravencti.collectors")


class BaseCollector(ABC):
    """Standard interface for all collectors."""

    name: str = ""
    source_name: str = ""
    retry_limit: int = 3
    retry_delay: float = 5.0

    def run(self):
        """Execute the collector with standard job tracking."""
        jid = job_start(self.name)
        t0 = time.monotonic()
        try:
            count = self.collect()
            elapsed = time.monotonic() - t0
            update_source(self.source_name, "success", count)
            job_done(jid, "completed", count)
            log.info("[%s] Completed: %d items in %.1fs", self.name, count, elapsed)
            return count
        except Exception as e:
            update_source(self.source_name, "error")
            job_done(jid, "failed", 0, str(e))
            log.exception("[%s] Failed", self.name)
            return 0

    def run_with_retry(self):
        """Run the collector with retry logic."""
        for attempt in range(1, self.retry_limit + 1):
            try:
                return self.run()
            except Exception as e:
                if attempt < self.retry_limit:
                    log.warning("[%s] Attempt %d/%d failed: %s — retrying in %.0fs",
                                self.name, attempt, self.retry_limit, e, self.retry_delay)
                    time.sleep(self.retry_delay * attempt)
                else:
                    log.error("[%s] All %d attempts failed", self.name, self.retry_limit)
                    return 0

    @abstractmethod
    def collect(self) -> int:
        """Override with collection logic. Return count of items collected."""
        ...


def job_start(job_type: str) -> int:
    from ravencti.db.connection import is_postgres
    with get_db() as conn:
        if is_postgres():
            cur = conn.execute(
                "INSERT INTO collection_jobs(job_type, status, started_at) VALUES(%s,%s,%s) RETURNING id",
                (job_type, "running", now_str()),
            )
            return cur.fetchone()[0]
        cur = conn.execute(
            "INSERT INTO collection_jobs(job_type, status, started_at) VALUES(?,?,?)",
            (job_type, "running", now_str()),
        )
        return cur.lastrowid


def job_done(jid: int, status: str, count: int, error: str | None = None) -> None:
    with get_db() as conn:
        conn.execute(
            "UPDATE collection_jobs "
            "SET status=?, completed_at=?, items_collected=?, error_message=? "
            "WHERE id=?",
            (status, now_str(), count, error, jid),
        )


def update_source(name: str, status: str, count: int = 0) -> None:
    _update_source(name, status, count)
