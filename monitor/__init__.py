"""
monitor/
--------
Continuous monitoring for SurfaceWatch.

A one-off scan says where a business stands today. This package is what turns
that into an early warning system: it rescans on a timer, works out what
changed since last time, and emails the owner only when something genuinely
needs them.

Modules
    scheduler.py   : runs scans automatically every 24 hours (APScheduler)
    diff_engine.py : explains what changed between two scans, in plain English
    alerts.py      : sends the plain English email when it matters

Re-exports are lazy (PEP 562) so that ``python -m monitor.scheduler`` does not
import the module twice, and so importing one part does not drag in the others.
"""

_EXPORTS = {
    "ScanScheduler":    "monitor.scheduler",
    "start_monitoring": "monitor.scheduler",
    "get_scheduler":    "monitor.scheduler",
    "run_full_scan":    "monitor.scheduler",
    "diff_latest_scans": "monitor.diff_engine",
    "diff_scan_files":  "monitor.diff_engine",
    "format_diff_text": "monitor.diff_engine",
    "DiffResult":       "monitor.diff_engine",
    "send_scan_alert":  "monitor.alerts",
    "decide_alerts":    "monitor.alerts",
    "check_certificate_expiry": "monitor.alerts",
}

__all__ = list(_EXPORTS)


def __getattr__(name: str):
    """Import a submodule only when one of its exports is actually used."""
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    import importlib
    return getattr(importlib.import_module(module_name), name)
