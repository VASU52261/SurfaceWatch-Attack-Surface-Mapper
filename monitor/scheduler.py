"""
monitor/scheduler.py
--------------------
Runs SurfaceWatch scans automatically, around the clock, without anyone
remembering to press a button.

A single scan tells a business owner where they stand today. Scheduled scans
tell them when something *changes* — a developer opens a port on Friday
evening, an old staging site reappears, a new weakness is published for
software they run. That is where the real value is for a business with no
security team.

What this module does, every 24 hours per monitored domain:

    1. Runs a full scan (subdomains, ports, services, CVEs)
    2. Saves it as ``scans/YYYY-MM-DD_HH-MM_domain.json``
    3. Compares it with the previous scan (``monitor/diff_engine.py``)
    4. Emails the owner if anything is worth their attention (``monitor/alerts.py``)

It uses APScheduler's ``BackgroundScheduler``, which runs in its own threads,
so a scan never blocks the Flask web server.

Standalone::

    python -m monitor.scheduler --target example.com --interval 24

Inside Flask (``run.py``)::

    from monitor.scheduler import ScanScheduler

    scheduler = ScanScheduler()
    scheduler.add_target("example.com")
    scheduler.start_with_flask(app)
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Optional

from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

DEFAULT_SCAN_DIR = "scans"
DEFAULT_PORTS    = "21,22,23,25,53,80,443,445,3306,3389,5432,8080,8443"
DEFAULT_INTERVAL_HOURS = 24


# ===========================================================================
# Where scans are stored
# ===========================================================================

def scan_filename(domain: str, when: Optional[datetime] = None) -> str:
    """
    Build the canonical scan filename: ``2026-08-03_06-55_example.com.json``.

    The timestamp comes first so that a plain alphabetical directory listing is
    also chronological order.
    """
    when = when or datetime.now()
    safe_domain = "".join(c for c in str(domain) if c.isalnum() or c in "-._")
    return f"{when.strftime('%Y-%m-%d_%H-%M')}_{safe_domain}.json"


def ensure_scan_dir(scan_dir: str = DEFAULT_SCAN_DIR) -> str:
    """Create the scan directory if it does not exist. Returns the path."""
    try:
        os.makedirs(scan_dir, exist_ok=True)
    except OSError as exc:
        log.error("Could not create scan directory %s: %s", scan_dir, exc)
    return scan_dir


# ===========================================================================
# Running one scan
# ===========================================================================

def run_full_scan(domain: str,
                  ports: str = DEFAULT_PORTS,
                  skip_cve: bool = False,
                  max_subdomains_to_portscan: int = 3):
    """
    Run every scanner against one domain and return the finished graph.

    This composes the existing scanners exactly as ``main.py`` does, so the
    scheduled scan and the manual one produce identical results. Optional
    Phase 4 scanners (Shodan, technology detection, screenshots) are picked up
    automatically once they exist, and skipped silently until then.

    Each stage is wrapped on its own: a failing port scan must not throw away
    the subdomains we already discovered.
    """
    from graph.builder import AttackSurfaceGraph

    graph = AttackSurfaceGraph(target=domain)
    graph.add_domain(domain)

    subdomains: list[str] = []

    # --- 1. subdomains ---------------------------------------------------
    try:
        from scanners.subdomain_enum import enumerate_subdomains
        subdomains = enumerate_subdomains(graph, domain) or []
        log.info("Found %d subdomains for %s", len(subdomains), domain)
    except Exception as exc:
        log.error("Subdomain discovery failed for %s: %s", domain, exc)

    # --- 2. ports and services -------------------------------------------
    try:
        from scanners.port_scanner import scan_ports
        scan_ports(graph, domain, ports=ports)
        for subdomain in subdomains[:max_subdomains_to_portscan]:
            try:
                scan_ports(graph, subdomain, ports=ports)
            except Exception as exc:
                log.error("Port scan failed for %s: %s", subdomain, exc)
    except Exception as exc:
        log.error("Port scanning failed for %s: %s", domain, exc)

    # --- 3. optional extra scanners (Phase 4) ----------------------------
    _run_optional_scanners(graph, domain)

    # --- 4. known weaknesses ---------------------------------------------
    if not skip_cve:
        try:
            from scanners.cve_lookup import lookup_cves_for_graph
            lookup_cves_for_graph(graph)
        except Exception as exc:
            log.error("CVE lookup failed for %s: %s", domain, exc)

    return graph


def _run_optional_scanners(graph, domain: str) -> None:
    """
    Run the Phase 4 scanners if they are present.

    Written so that this module works before those files exist, and picks them
    up without modification once they do.
    """
    optional = (
        ("scanners.tech_detect",     "detect_technologies"),
        ("scanners.shodan_scanner",  "enrich_graph_with_shodan"),
        ("scanners.screenshot",      "capture_screenshots"),
    )

    for module_name, function_name in optional:
        try:
            module = __import__(module_name, fromlist=[function_name])
            function = getattr(module, function_name, None)
            if function is None:
                continue
            function(graph)
            log.info("Ran optional scanner: %s", module_name)
        except ImportError:
            log.debug("Optional scanner not installed yet: %s", module_name)
        except Exception as exc:
            log.error("Optional scanner %s failed: %s", module_name, exc)


# ===========================================================================
# Monitored targets
# ===========================================================================

@dataclass
class MonitoredTarget:
    """One domain being watched, and how it should be scanned."""

    domain: str
    ports: str = DEFAULT_PORTS
    skip_cve: bool = False
    interval_hours: float = DEFAULT_INTERVAL_HOURS
    alert: bool = True
    last_run: Optional[str] = None
    last_error: str = ""
    run_count: int = 0

    @property
    def job_id(self) -> str:
        return f"surfacewatch-scan:{self.domain}"

    def to_dict(self) -> dict:
        return {
            "domain":         self.domain,
            "ports":          self.ports,
            "skip_cve":       self.skip_cve,
            "interval_hours": self.interval_hours,
            "alert":          self.alert,
            "last_run":       self.last_run,
            "last_error":     self.last_error,
            "run_count":      self.run_count,
        }


def targets_from_env() -> list[str]:
    """
    Read the domains to monitor from ``SURFACEWATCH_TARGETS`` in ``.env``::

        SURFACEWATCH_TARGETS=example.com,another-business.co.uk
    """
    raw = os.getenv("SURFACEWATCH_TARGETS", "")
    return [d.strip() for d in raw.replace(";", ",").split(",") if d.strip()]


# ===========================================================================
# The scheduler
# ===========================================================================

class ScanScheduler:
    """
    Runs scans on a timer, in the background, for any number of domains.

    Args:
        scan_dir       : where scan JSON files are written
        interval_hours : how often each domain is rescanned (default 24)
        send_alerts    : email the owner when something needs attention
        dry_run_alerts : build alert emails but do not actually send them
        on_scan_complete: optional callback ``(domain, graph, diff) -> None``,
                          handy for pushing live updates into the web UI

    Every domain gets its own job. Jobs are configured with ``coalesce`` and
    ``max_instances=1`` so that a scan running long can never stack up behind
    itself and hammer the target.
    """

    def __init__(self,
                 scan_dir: str = DEFAULT_SCAN_DIR,
                 interval_hours: float = DEFAULT_INTERVAL_HOURS,
                 send_alerts: bool = True,
                 dry_run_alerts: bool = False,
                 on_scan_complete: Optional[Callable[..., None]] = None):
        self.scan_dir         = ensure_scan_dir(scan_dir)
        self.interval_hours   = interval_hours
        self.send_alerts      = send_alerts
        self.dry_run_alerts   = dry_run_alerts
        self.on_scan_complete = on_scan_complete

        self.targets: dict[str, MonitoredTarget] = {}
        self._lock = threading.Lock()
        self._scheduler = None
        self._started = False

    # ------------------------------------------------------------------
    # Target management
    # ------------------------------------------------------------------

    def add_target(self,
                   domain: str,
                   ports: str = DEFAULT_PORTS,
                   skip_cve: bool = False,
                   interval_hours: Optional[float] = None,
                   alert: bool = True,
                   run_now: bool = False) -> MonitoredTarget:
        """
        Start monitoring a domain. Safe to call while the scheduler is running.

        Adding a domain that is already monitored updates its settings rather
        than creating a duplicate job.
        """
        domain = str(domain).strip().lower()
        if not domain:
            raise ValueError("A domain is required.")

        target = MonitoredTarget(
            domain=domain,
            ports=ports,
            skip_cve=skip_cve,
            interval_hours=interval_hours or self.interval_hours,
            alert=alert,
        )

        with self._lock:
            existing = self.targets.get(domain)
            if existing:
                target.last_run  = existing.last_run
                target.run_count = existing.run_count
            self.targets[domain] = target

        if self._started:
            self._schedule_job(target, run_now=run_now)

        log.info("Now monitoring %s every %s hours", domain, target.interval_hours)
        return target

    def remove_target(self, domain: str) -> bool:
        """Stop monitoring a domain. Returns True if it was being monitored."""
        domain = str(domain).strip().lower()
        with self._lock:
            target = self.targets.pop(domain, None)

        if not target:
            return False

        if self._scheduler:
            try:
                self._scheduler.remove_job(target.job_id)
            except Exception as exc:
                log.debug("Could not remove job for %s: %s", domain, exc)

        log.info("Stopped monitoring %s", domain)
        return True

    def list_targets(self) -> list[dict]:
        """Everything currently being monitored, for the dashboard or the CLI."""
        with self._lock:
            return [t.to_dict() for t in self.targets.values()]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self, run_now: bool = False) -> bool:
        """
        Start the background scheduler.

        Returns False (rather than raising) if APScheduler is not installed, so
        the rest of SurfaceWatch keeps working without scheduled monitoring.
        """
        if self._started:
            log.debug("Scheduler already running.")
            return True

        try:
            from apscheduler.schedulers.background import BackgroundScheduler
        except ImportError:
            log.error(
                "APScheduler is not installed, so automatic monitoring is off. "
                "Install it with:  pip install apscheduler"
            )
            return False

        try:
            self._scheduler = BackgroundScheduler(
                daemon=True,
                job_defaults={
                    "coalesce": True,       # one catch-up run, not a backlog
                    "max_instances": 1,     # never scan the same domain twice at once
                    "misfire_grace_time": 3600,
                },
            )
            self._scheduler.start()
            self._started = True
        except Exception as exc:
            log.error("Could not start the scheduler: %s", exc)
            return False

        with self._lock:
            targets = list(self.targets.values())
        for target in targets:
            self._schedule_job(target, run_now=run_now)

        log.info("SurfaceWatch monitoring started for %d domain(s).", len(targets))
        return True

    def start_with_flask(self, app=None, run_now: bool = False) -> bool:
        """
        Start monitoring alongside a Flask app, without blocking it.

        Flask's development reloader runs the module twice; this guard makes
        sure scans are only scheduled in the child process, so a domain is not
        scanned twice each cycle in debug mode.
        """
        if app is not None and app.debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
            log.debug("Skipping scheduler start in the Flask reloader parent process.")
            return False
        return self.start(run_now=run_now)

    def shutdown(self, wait: bool = False) -> None:
        """Stop the scheduler. Safe to call even if it never started."""
        if self._scheduler and self._started:
            try:
                self._scheduler.shutdown(wait=wait)
                log.info("SurfaceWatch monitoring stopped.")
            except Exception as exc:
                log.debug("Scheduler shutdown problem: %s", exc)
        self._started = False

    def _schedule_job(self, target: MonitoredTarget, run_now: bool = False) -> None:
        """Register (or replace) the recurring job for one target."""
        if not self._scheduler:
            return

        try:
            from apscheduler.triggers.interval import IntervalTrigger

            options: dict[str, Any] = {
                "func":             self.scan_once,
                "trigger":          IntervalTrigger(hours=target.interval_hours),
                "args":             [target.domain],
                "id":               target.job_id,
                "name":             f"SurfaceWatch scan of {target.domain}",
                "replace_existing": True,
            }
            # Only pass next_run_time when we actually want an immediate run.
            # APScheduler treats an explicit next_run_time=None as "create this
            # job paused", which would silently stop the 24-hour scans from
            # ever firing.
            if run_now:
                options["next_run_time"] = datetime.now()

            self._scheduler.add_job(**options)
            log.info("Scheduled %s every %s hours", target.domain, target.interval_hours)
        except Exception as exc:
            log.error("Could not schedule %s: %s", target.domain, exc)

    # ------------------------------------------------------------------
    # The job itself
    # ------------------------------------------------------------------

    def scan_once(self, domain: str) -> dict:
        """
        Scan one domain, save it, compare it with last time, and alert.

        This is what the scheduler calls on a timer, and what the CLI calls for
        a one-off run. It never raises: a failure is recorded on the target and
        logged, so tomorrow's scan still happens.
        """
        started = datetime.now()
        outcome: dict[str, Any] = {
            "domain": domain, "started": started.isoformat(timespec="seconds"),
            "scan_file": "", "changes": 0, "alert": None, "error": "",
        }

        with self._lock:
            target = self.targets.get(domain)
        if target is None:
            target = MonitoredTarget(domain=domain)

        log.info("=" * 60)
        log.info("Scheduled scan starting for %s", domain)
        log.info("=" * 60)

        try:
            graph = run_full_scan(domain, ports=target.ports, skip_cve=target.skip_cve)

            # --- save -----------------------------------------------------
            path = os.path.join(self.scan_dir, scan_filename(domain, started))
            graph.save(path)
            outcome["scan_file"] = path
            log.info("Scan saved to %s", path)

            # --- compare with the previous scan ---------------------------
            diff = None
            try:
                from monitor.diff_engine import diff_latest_scans
                diff = diff_latest_scans(self.scan_dir, domain)
                if diff:
                    outcome["changes"] = len(diff.changes)
                    log.info("Since last time: %s", diff.summary_line)
            except Exception as exc:
                log.error("Could not compare with the previous scan: %s", exc)

            # --- alert ----------------------------------------------------
            if self.send_alerts and target.alert:
                try:
                    from monitor.alerts import send_scan_alert
                    from reports.plain_english import generate_report

                    report = generate_report(graph)
                    outcome["alert"] = send_scan_alert(
                        domain, report=report, diff=diff,
                        dry_run=self.dry_run_alerts,
                    )
                except Exception as exc:
                    log.error("Alerting failed for %s: %s", domain, exc)

            # --- notify the app -------------------------------------------
            if self.on_scan_complete:
                try:
                    self.on_scan_complete(domain, graph, diff)
                except Exception as exc:
                    log.error("Scan-complete callback failed: %s", exc)

            target.last_error = ""

        except Exception as exc:
            log.error("Scheduled scan of %s failed: %s", domain, exc)
            outcome["error"]  = str(exc)
            target.last_error = str(exc)

        finally:
            target.last_run  = started.isoformat(timespec="seconds")
            target.run_count += 1
            with self._lock:
                self.targets[domain] = target

            elapsed = (datetime.now() - started).total_seconds()
            log.info("Scan of %s finished in %.0f seconds", domain, elapsed)

        return outcome

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def next_run_times(self) -> dict[str, str]:
        """When each domain is due to be scanned next, for the dashboard."""
        if not self._scheduler:
            return {}

        schedule: dict[str, str] = {}
        for job in self._scheduler.get_jobs():
            when = getattr(job, "next_run_time", None)
            domain = job.id.split(":", 1)[-1]
            schedule[domain] = when.strftime("%d %b %Y at %H:%M") if when else "not scheduled"
        return schedule

    @property
    def is_running(self) -> bool:
        return self._started


# ===========================================================================
# Module-level convenience
# ===========================================================================

_default_scheduler: Optional[ScanScheduler] = None


def get_scheduler(**kwargs) -> ScanScheduler:
    """
    Get the shared scheduler, creating it the first time.

    Flask blueprints and the CLI both use this so that they are all talking to
    the same set of monitored domains.
    """
    global _default_scheduler
    if _default_scheduler is None:
        _default_scheduler = ScanScheduler(**kwargs)
    return _default_scheduler


def start_monitoring(app=None,
                     domains: Optional[list[str]] = None,
                     interval_hours: float = DEFAULT_INTERVAL_HOURS,
                     run_now: bool = False,
                     **kwargs) -> ScanScheduler:
    """
    One-line setup, intended for ``run.py``::

        from monitor.scheduler import start_monitoring
        start_monitoring(app, ["example.com"])

    Domains default to whatever ``SURFACEWATCH_TARGETS`` lists in ``.env``.
    """
    scheduler = get_scheduler(interval_hours=interval_hours, **kwargs)

    for domain in (domains if domains is not None else targets_from_env()):
        scheduler.add_target(domain, interval_hours=interval_hours)

    scheduler.start_with_flask(app, run_now=run_now)
    return scheduler


# ===========================================================================
# CLI:  python -m monitor.scheduler --target example.com --interval 24
# ===========================================================================

if __name__ == "__main__":
    import argparse
    import time

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(
        description="Run SurfaceWatch scans automatically on a schedule."
    )
    parser.add_argument("--target", action="append", default=[],
                        help="Domain to monitor (repeat for several)")
    parser.add_argument("--interval", type=float, default=DEFAULT_INTERVAL_HOURS,
                        help="Hours between scans (default: 24)")
    parser.add_argument("--ports", default=DEFAULT_PORTS, help="Ports to scan")
    parser.add_argument("--scan-dir", default=DEFAULT_SCAN_DIR,
                        help="Where to store scan history")
    parser.add_argument("--skip-cve", action="store_true",
                        help="Skip the CVE lookup (much faster)")
    parser.add_argument("--once", action="store_true",
                        help="Scan once and exit, instead of staying resident")
    parser.add_argument("--no-alerts", action="store_true",
                        help="Do not send alert emails")
    args = parser.parse_args()

    domains_to_watch = args.target or targets_from_env()
    if not domains_to_watch:
        raise SystemExit(
            "No domain given. Use --target example.com, or set SURFACEWATCH_TARGETS "
            "in your .env file."
        )

    monitor = ScanScheduler(
        scan_dir=args.scan_dir,
        interval_hours=args.interval,
        send_alerts=not args.no_alerts,
    )
    for watched in domains_to_watch:
        monitor.add_target(watched, ports=args.ports, skip_cve=args.skip_cve)

    if args.once:
        for watched in domains_to_watch:
            monitor.scan_once(watched)
        raise SystemExit(0)

    if not monitor.start(run_now=True):
        raise SystemExit("Could not start the scheduler.")

    print(f"\nSurfaceWatch is monitoring {len(domains_to_watch)} domain(s) "
          f"every {args.interval} hours.")
    print("Press Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        monitor.shutdown()
        print("\nMonitoring stopped.")
