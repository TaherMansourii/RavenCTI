"""
app.py — RavenCTI application factory.

Usage:
  python app.py                   # development server
  gunicorn "app:create_app()"     # production

Environment:
  Copy .env.example to .env and fill in FLASK_SECRET_KEY at minimum.
"""
import atexit
import logging
import os
import signal
import sys

from flask import Flask
from flask_cors import CORS


def create_app() -> Flask:
    """
    Application factory.
    Creates the Flask app, registers blueprints, initialises the DB,
    and starts the scheduler.
    """
    # ── Logging ───────────────────────────────────────────────────────────────
    from ravencti.config import LOG_DIR
    from ravencti.utils.logging import setup_logging
    setup_logging(LOG_DIR, level=os.environ.get("LOG_LEVEL", "INFO"))

    log = logging.getLogger("ravencti.app")

    # ── Flask app ─────────────────────────────────────────────────────────────
    from ravencti.config import BASE_DIR, FLASK_SECRET_KEY
    app = Flask(__name__, static_folder=str(BASE_DIR))
    app.secret_key = FLASK_SECRET_KEY
    app.config["JSON_SORT_KEYS"] = False

    CORS(app)

    # ── Database ──────────────────────────────────────────────────────────────
    from ravencti.db.schema import init_db
    init_db()
    log.info("Database ready")

    # ── Blueprints ────────────────────────────────────────────────────────────
    from ravencti.routes.scans     import bp as scans_bp
    from ravencti.routes.cves      import bp as cves_bp
    from ravencti.routes.assets    import bp as assets_bp
    from ravencti.routes.exposure  import bp as exposure_bp
    from ravencti.routes.misc      import bp as misc_bp
    from ravencti.routes.auth_ui   import bp as auth_ui_bp

    for bp in (auth_ui_bp, scans_bp, cves_bp, assets_bp, exposure_bp, misc_bp):
        app.register_blueprint(bp)

    log.info("Blueprints registered")

    # ── Scheduler ─────────────────────────────────────────────────────────────
    _start_scheduler(log)

    return app


def _start_scheduler(log: logging.Logger) -> None:
    """Build and start APScheduler; register clean shutdown handler."""
    from ravencti.collectors.cve      import collect_cves, collect_kev, collect_epss
    from ravencti.collectors.ransomware import collect_ransomware
    from ravencti.collectors.mitre    import collect_mitre
    from ravencti.collectors.cleanup  import cleanup_stale_data
    from ravencti.collectors.exposure import (
        collect_reddit_exposure, collect_github_exposure,
        collect_telegram_exposure, collect_paste_exposure,
        collect_crtsh_exposure, collect_dork_exposure,
    )
    from ravencti.collectors.darkforums import collect_darkforums
    from ravencti.collectors.patched import collect_patched
    from ravencti.collectors.cracked import collect_cracked
    from ravencti.collectors.twitter import collect_twitter
    from ravencti.services.queue import build_scheduler

    collectors = {
        "cves":       collect_cves,
        "ransomware": collect_ransomware,
        "kev":        collect_kev,
        "epss":       collect_epss,
        "mitre":      collect_mitre,
        "cleanup":    cleanup_stale_data,
        "reddit":     collect_reddit_exposure,
        "github":     collect_github_exposure,
        "telegram":   collect_telegram_exposure,
        "paste":      collect_paste_exposure,
        "crtsh":      collect_crtsh_exposure,
        "dork":       collect_dork_exposure,
        "darkforums": collect_darkforums,
        "patched":    collect_patched,
        "cracked":    collect_cracked,
        "twitter":    collect_twitter,
    }

    sch = build_scheduler(collectors)
    if sch is None:
        log.warning("APScheduler not available — scheduled jobs disabled")
        return

    sch.start()
    log.info("Scheduler started with %d jobs", len(sch.get_jobs()))

    def _shutdown():
        log.info("Shutting down scheduler…")
        try:
            sch.shutdown(wait=False)
        except Exception:
            pass

    atexit.register(_shutdown)

    def _signal_handler(sig, _frame):
        log.info("Signal %s received — shutting down", sig)
        _shutdown()
        sys.exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _signal_handler)
        except (OSError, ValueError):
            pass   # not on main thread — gunicorn manages signals


# ── Dev server entry point ────────────────────────────────────────────────────
if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("PORT", 5000))
    app.run(
        host="0.0.0.0",
        port=port,
        debug=os.environ.get("FLASK_DEBUG", "0") == "1",
        use_reloader=False,   # reloader spawns a second process → duplicate scheduler
    )