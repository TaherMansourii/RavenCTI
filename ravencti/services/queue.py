"""
services/queue.py — Background job queue and scheduler.

Design:
  - Single daemon thread processes jobs sequentially (SQLite-safe)
  - APScheduler enqueues jobs; the worker executes them
  - Duplicate job detection prevents the same job from queuing twice
  - Clean shutdown drains the queue before exit
"""
import logging
import threading
from queue import Queue, Empty

log = logging.getLogger("ravencti.queue")

_jq: Queue = Queue()
_active_jobs: set[str] = set()
_active_lock = threading.Lock()


def _worker() -> None:
    """Daemon thread: dequeue and execute jobs one at a time."""
    import time as _time
    while True:
        try:
            fn, name = _jq.get(timeout=1)
        except Empty:
            continue
        log.info("[Q] Starting: %-20s  (queue depth: %d)", name, _jq.qsize())
        t0 = _time.monotonic()
        try:
            fn()
            elapsed = _time.monotonic() - t0
            log.info("[Q] Finished: %-20s  (%.1fs)", name, elapsed)
        except Exception:
            elapsed = _time.monotonic() - t0
            log.exception("[Q] Failed:   %-20s  (%.1fs)", name, elapsed)
        finally:
            with _active_lock:
                _active_jobs.discard(name)
            _jq.task_done()


# Start the worker daemon thread at import time
_thread = threading.Thread(target=_worker, daemon=True, name="raven-worker")
_thread.start()


def enqueue(fn, name: str) -> dict:
    """
    Add a job to the queue.

    If a job with the same name is already queued or running, it is skipped
    to prevent duplicate concurrent scans.
    """
    with _active_lock:
        if name in _active_jobs:
            log.debug("[Q] Skipping duplicate job: %s", name)
            return {"status": "skipped", "job": name, "reason": "already_queued"}
        _active_jobs.add(name)

    _jq.put((fn, name))
    depth = _jq.qsize()
    log.info("[Q] Enqueued: %s (queue depth: %d)", name, depth)
    return {"status": "queued", "job": name, "depth": depth}


def queue_depth() -> int:
    return _jq.qsize()


def drain(timeout: float = 30.0) -> None:
    """Wait for all queued jobs to finish (used before reset/shutdown)."""
    import time
    deadline = time.time() + timeout
    while not _jq.empty() and time.time() < deadline:
        time.sleep(0.25)


# ── APScheduler setup ──────────────────────────────────────────────────────────
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    HAS_SCHEDULER = True
except ImportError:
    HAS_SCHEDULER = False
    log.warning("APScheduler not installed — scheduled jobs disabled")


def build_scheduler(collectors: dict) -> "BackgroundScheduler | None":
    """
    Create and return a configured APScheduler instance.

    `collectors` is a dict mapping name → callable, provided by the
    app factory to avoid circular imports.

    Raises: nothing — returns None if APScheduler is unavailable.
    """
    if not HAS_SCHEDULER:
        return None

    sch = BackgroundScheduler(
        job_defaults={
            "coalesce":       True,    # merge missed runs into one
            "max_instances":  1,       # never run the same job twice
            "misfire_grace_time": 300, # 5 min grace before a missed run is dropped
        }
    )

    def _add(name: str, cron: str) -> None:
        fn = collectors.get(name)
        if fn is None:
            log.warning("Scheduler: unknown collector '%s'", name)
            return
        trigger = CronTrigger.from_crontab(cron)
        sch.add_job(
            lambda f=fn, n=name: enqueue(f, n),
            trigger=trigger,
            id=name,
            replace_existing=True,
        )
        log.debug("Scheduled: %s  cron='%s'", name, cron)

    # ── Schedule ──────────────────────────────────────────────────────────────
    _add("cves",        "0 2 * * *")      # 02:00 daily
    _add("ransomware",  "0 */4 * * *")    # every 4 hours
    _add("kev",         "0 3 * * *")      # 03:00 daily
    _add("epss",        "0 4 * * *")      # 04:00 daily
    _add("mitre",       "0 6 * * 1")      # 06:00 Monday
    _add("cleanup",     "30 1 * * *")     # 01:30 daily
    _add("reddit",      "0 */6 * * *")    # every 6 hours
    _add("github",      "0 */8 * * *")    # every 8 hours
    _add("telegram",    "0 */4 * * *")    # every 4 hours
    _add("paste",       "0 */6 * * *")    # every 6 hours
    _add("crtsh",       "0 */12 * * *")   # every 12 hours
    _add("dork",        "0 */8 * * *")    # every 8 hours
    _add("darkforums",  "0 */8 * * *")    # every 8 hours
    _add("patched",     "0 */8 * * *")    # every 8 hours
    _add("cracked",     "0 */8 * * *")    # every 8 hours
    _add("twitter",     "0 */4 * * *")    # every 4 hours

    return sch