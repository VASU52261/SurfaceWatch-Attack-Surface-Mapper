"""
monitor/diff_engine.py
----------------------
Compares two scans of the same business and explains what changed, in plain
English.

Monitoring is what turns a one-off scan into something genuinely useful. A
business owner cannot read a report every day, but they *can* read one line
that says "two new addresses appeared overnight, and one of them has no
encryption".

What it detects:

    * new subdomains          * removed subdomains
    * newly opened ports      * ports that closed
    * new vulnerabilities     * vulnerabilities that were fixed
    * risk score movement     * new services and technologies

Every change carries a plain English sentence and a severity, so the alert
layer (``monitor/alerts.py``) can decide what is worth waking someone up for.

Typical use::

    from monitor.diff_engine import diff_latest_scans, format_diff_text

    result = diff_latest_scans("scans", "acme-plumbing.com")
    if result and result.has_changes:
        print(format_diff_text(result))
"""

from __future__ import annotations

import glob
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from graph.builder import AttackSurfaceGraph
from reports.plain_english import (
    PORT_PROFILES,
    Severity,
    _label,
    _meta,
    _node_type,
    _safe_float,
    _safe_int,
    _wrap,
    cvss_to_severity,
    describe_subdomain,
    describe_vulnerability,
    friendly_name,
    generate_findings,
    overall_risk_score,
)

log = logging.getLogger(__name__)

#: Filenames look like ``2026-08-03_06-55_acme-plumbing.com.json``.
SCAN_FILENAME_RE = re.compile(
    r"^(?P<stamp>\d{4}-\d{2}-\d{2}_\d{2}-\d{2})_(?P<domain>.+)\.json$"
)

#: A risk score rise of more than this percentage is worth telling someone about.
RISK_INCREASE_ALERT_PCT = 20.0


# ===========================================================================
# Change records
# ===========================================================================

@dataclass
class Change:
    """
    One thing that changed between two scans.

    Attributes:
        kind     : machine-readable type, e.g. "new_subdomain", "new_cve"
        severity : CRITICAL / HIGH / MEDIUM / LOW
        plain    : the sentence a business owner reads
        warning  : extra plain English concern, e.g. "no HTTPS"
        node_id  : the underlying graph node (technical)
        good_news: True when the change is an improvement
    """

    kind: str
    severity: str
    plain: str
    warning: str = ""
    node_id: str = ""
    good_news: bool = False

    def to_dict(self) -> dict:
        return {
            "kind":      self.kind,
            "severity":  self.severity,
            "plain":     self.plain,
            "warning":   self.warning,
            "node_id":   self.node_id,
            "good_news": self.good_news,
        }


@dataclass
class DiffResult:
    """The complete "what changed since last time" answer."""

    domain: str = ""
    old_scan: str = ""
    new_scan: str = ""
    old_time: str = ""
    new_time: str = ""

    changes: list[Change] = field(default_factory=list)

    old_risk_score: float = 0.0
    new_risk_score: float = 0.0
    risk_change_pct: float = 0.0

    # ---- convenience views ----------------------------------------------

    @property
    def has_changes(self) -> bool:
        return bool(self.changes)

    def of_kind(self, *kinds: str) -> list[Change]:
        return [c for c in self.changes if c.kind in kinds]

    @property
    def bad_news(self) -> list[Change]:
        return [c for c in self.changes if not c.good_news]

    @property
    def good_news(self) -> list[Change]:
        return [c for c in self.changes if c.good_news]

    @property
    def has_critical(self) -> bool:
        return any(c.severity == Severity.CRITICAL and not c.good_news
                   for c in self.changes)

    @property
    def risk_increased_sharply(self) -> bool:
        """True when the risk score jumped by more than the alert threshold."""
        return self.risk_change_pct > RISK_INCREASE_ALERT_PCT

    @property
    def summary_line(self) -> str:
        """One sentence for an email subject or a dashboard banner."""
        if not self.has_changes:
            return f"No changes on {self.domain} since the last check."

        parts = []
        headline_counts = [
            ("new_subdomain", "new address",   "new addresses"),
            ("new_port",      "new open door", "new open doors"),
            ("new_cve",       "new weakness",  "new weaknesses"),
        ]
        for kind, singular, plural in headline_counts:
            count = len(self.of_kind(kind))
            if count:
                parts.append(f"{count} {singular if count == 1 else plural}")

        if not parts:
            return f"{len(self.changes)} changes on {self.domain} since the last check."
        return f"{', '.join(parts)} on {self.domain} since the last check."

    def to_dict(self) -> dict:
        return {
            "domain":          self.domain,
            "old_scan":        self.old_scan,
            "new_scan":        self.new_scan,
            "old_time":        self.old_time,
            "new_time":        self.new_time,
            "old_risk_score":  self.old_risk_score,
            "new_risk_score":  self.new_risk_score,
            "risk_change_pct": self.risk_change_pct,
            "has_changes":     self.has_changes,
            "has_critical":    self.has_critical,
            "summary_line":    self.summary_line,
            "changes":         [c.to_dict() for c in self.changes],
        }


# ===========================================================================
# Reading scan files
# ===========================================================================

def parse_scan_filename(path: str) -> tuple[Optional[datetime], str]:
    """
    Pull the timestamp and domain out of a scan filename.

    Returns ``(datetime or None, domain)``. Files that do not follow the
    convention are not an error — they simply have no timestamp.
    """
    name  = os.path.basename(path)
    match = SCAN_FILENAME_RE.match(name)
    if not match:
        return None, ""
    try:
        when = datetime.strptime(match.group("stamp"), "%Y-%m-%d_%H-%M")
    except ValueError:
        when = None
    return when, match.group("domain")


def list_scans(scan_dir: str = "scans", domain: str = "") -> list[str]:
    """
    All saved scans for a domain, oldest first.

    Sorted by the timestamp in the filename where possible, falling back to
    file modification time so a hand-copied file still slots into place.
    """
    if not os.path.isdir(scan_dir):
        return []

    pattern = os.path.join(scan_dir, f"*_{domain}.json" if domain else "*.json")
    files   = [f for f in glob.glob(pattern) if os.path.isfile(f)]

    def sort_key(path: str):
        when, _domain = parse_scan_filename(path)
        if when:
            return when.timestamp()
        try:
            return os.path.getmtime(path)
        except OSError:
            return 0.0

    return sorted(files, key=sort_key)


def load_scan(path: str) -> Optional[AttackSurfaceGraph]:
    """Load a saved scan, returning ``None`` rather than raising on failure."""
    try:
        return AttackSurfaceGraph.load(path)
    except FileNotFoundError:
        log.error("Scan file not found: %s", path)
    except Exception as exc:
        log.error("Could not read scan file %s: %s", path, exc)
    return None


# ===========================================================================
# Extracting comparable facts from a graph
# ===========================================================================

def _snapshot(graph) -> dict[str, Any]:
    """
    Reduce a graph to the handful of facts worth comparing between scans.

    Everything is keyed by a stable identifier so that set arithmetic gives us
    the additions and removals directly.
    """
    subdomains: dict[str, dict] = {}
    ports:      dict[str, dict] = {}
    cves:       dict[str, dict] = {}
    services:   dict[str, dict] = {}

    for node_id, attrs in graph.G.nodes(data=True):
        node_type = attrs.get("node_type", "")
        meta      = attrs.get("meta") if isinstance(attrs.get("meta"), dict) else {}

        if node_type == "subdomain":
            subdomains[node_id] = {"label": attrs.get("label", node_id)}

        elif node_type == "port":
            ports[node_id] = {
                "label":    attrs.get("label", node_id),
                "port":     _safe_int(meta.get("port")),
                "protocol": meta.get("protocol", "tcp"),
            }

        elif node_type == "service":
            services[node_id] = {
                "label":   attrs.get("label", node_id),
                "version": meta.get("version", ""),
            }

        elif node_type == "cve" or str(node_id).upper().startswith("CVE-"):
            cves[node_id] = {
                "cvss":        _safe_float(meta.get("cvss"),
                                           _safe_float(attrs.get("risk_score"))),
                "description": meta.get("description", ""),
            }

    return {
        "subdomains": subdomains,
        "ports":      ports,
        "services":   services,
        "cves":       cves,
    }


def _host_of_port(port_id: str) -> str:
    """``192.0.2.1:3306/tcp`` -> ``192.0.2.1``."""
    return str(port_id).split(":")[0]


def _subdomain_warnings(graph, subdomain_id: str) -> str:
    """
    Plain English concerns about a newly discovered address.

    This produces the "(WARNING: no HTTPS, publicly accessible)" part of the
    diff report, which is what makes a new-subdomain alert actionable rather
    than merely informative.
    """
    warnings: list[str] = []

    label = _label(graph, subdomain_id)
    role, should_be_public, _concern = describe_subdomain(label)

    if not should_be_public:
        warnings.append(f"this looks like {role}")

    # Look at the ports on whatever this address resolves to.
    try:
        neighbours = set(graph.G.successors(subdomain_id)) | set(graph.G.predecessors(subdomain_id))
    except Exception:
        neighbours = set()

    open_ports: set[int] = set()
    for neighbour in neighbours:
        if _node_type(graph, neighbour) != "ip":
            continue
        for candidate in graph.G.successors(neighbour):
            if _node_type(graph, candidate) == "port":
                open_ports.add(_safe_int(_meta(graph, candidate).get("port")))

    if 80 in open_ports and not ({443, 8443} & open_ports):
        warnings.append("no HTTPS")

    risky = sorted(
        p for p in open_ports
        if PORT_PROFILES.get(p, {}).get("severity") == Severity.CRITICAL
    )
    for port in risky[:2]:
        warnings.append(f"{PORT_PROFILES[port]['name']} is open to everyone")

    if not warnings:
        warnings.append("publicly accessible")

    return ", ".join(warnings)


# ===========================================================================
# The comparison itself
# ===========================================================================

def diff_graphs(old_graph, new_graph, domain: str = "") -> DiffResult:
    """
    Compare two scans and return every change, described in plain English.

    The new graph is the source of truth for describing things: an address
    that just appeared has to be explained using what we know about it *now*.
    """
    result = DiffResult(domain=domain or getattr(new_graph, "target", "") or "")

    old = _snapshot(old_graph)
    new = _snapshot(new_graph)

    # ---- subdomains -----------------------------------------------------
    for node_id in sorted(set(new["subdomains"]) - set(old["subdomains"])):
        label   = new["subdomains"][node_id]["label"]
        warning = _subdomain_warnings(new_graph, node_id)
        role, should_be_public, _c = describe_subdomain(label)

        result.changes.append(Change(
            kind="new_subdomain",
            severity=Severity.HIGH if not should_be_public else Severity.MEDIUM,
            plain=f"{label} is new since the last check.",
            warning=warning,
            node_id=node_id,
        ))

    for node_id in sorted(set(old["subdomains"]) - set(new["subdomains"])):
        label = old["subdomains"][node_id]["label"]
        result.changes.append(Change(
            kind="removed_subdomain",
            severity=Severity.LOW,
            plain=f"{label} has disappeared - it no longer answers.",
            warning="if you did not take this offline on purpose, ask why it vanished",
            node_id=node_id,
        ))

    # ---- ports ----------------------------------------------------------
    for node_id in sorted(set(new["ports"]) - set(old["ports"])):
        info    = new["ports"][node_id]
        port    = info["port"]
        host    = _host_of_port(node_id)
        profile = PORT_PROFILES.get(port)

        if profile:
            severity = profile["severity"]
            plain = (
                f"The {profile['name']} door on {host} has been opened to the "
                f"internet since the last check."
            )
            warning = profile["attack"]
        else:
            severity = Severity.MEDIUM
            plain = f"Port {port} on {host} has been opened to the internet."
            warning = "nobody may have meant to open this - worth asking about"

        result.changes.append(Change(
            kind="new_port", severity=severity, plain=plain,
            warning=warning, node_id=node_id,
        ))

    for node_id in sorted(set(old["ports"]) - set(new["ports"])):
        info    = old["ports"][node_id]
        port    = info["port"]
        host    = _host_of_port(node_id)
        profile = PORT_PROFILES.get(port)
        name    = profile["name"] if profile else f"port {port}"

        result.changes.append(Change(
            kind="closed_port",
            severity=Severity.LOW,
            plain=f"The {name} door on {host} is now closed. That is one less way in.",
            node_id=node_id,
            good_news=True,
        ))

    # ---- vulnerabilities ------------------------------------------------
    for node_id in sorted(set(new["cves"]) - set(old["cves"])):
        info = new["cves"][node_id]
        cvss = info["cvss"]
        what_it_does, _gain = describe_vulnerability(info["description"], cvss)
        affected = _affected_asset(new_graph, node_id)

        result.changes.append(Change(
            kind="new_cve",
            severity=cvss_to_severity(cvss),
            plain=(
                f"A new security weakness was found on {affected}. It {what_it_does}."
            ),
            warning="the fix is usually a software update",
            node_id=node_id,
        ))

    for node_id in sorted(set(old["cves"]) - set(new["cves"])):
        affected = _affected_asset(old_graph, node_id)
        result.changes.append(Change(
            kind="resolved_cve",
            severity=Severity.LOW,
            plain=f"A security weakness on {affected} has been fixed. Well done.",
            node_id=node_id,
            good_news=True,
        ))

    # ---- services -------------------------------------------------------
    for node_id in sorted(set(new["services"]) - set(old["services"])):
        result.changes.append(Change(
            kind="new_service",
            severity=Severity.MEDIUM,
            plain=(
                f"New software is now running and reachable from the internet: "
                f"{friendly_name(new_graph, node_id)}."
            ),
            warning="check this was installed on purpose",
            node_id=node_id,
        ))

    # ---- risk score -----------------------------------------------------
    try:
        result.old_risk_score = overall_risk_score(generate_findings(old_graph))
        result.new_risk_score = overall_risk_score(generate_findings(new_graph))
        result.risk_change_pct = _percent_change(result.old_risk_score,
                                                 result.new_risk_score)
    except Exception as exc:
        log.error("Could not compare risk scores: %s", exc)

    if result.risk_increased_sharply:
        result.changes.append(Change(
            kind="risk_increase",
            severity=Severity.HIGH,
            plain=describe_risk_change(result.old_risk_score,
                                       result.new_risk_score,
                                       result.risk_change_pct),
            warning="something changed for the worse - the items above explain what",
        ))
    elif result.risk_change_pct <= -RISK_INCREASE_ALERT_PCT:
        result.changes.append(Change(
            kind="risk_decrease",
            severity=Severity.LOW,
            plain=(
                describe_risk_change(result.old_risk_score, result.new_risk_score,
                                     result.risk_change_pct)
                + " Whatever you did, it worked."
            ),
            good_news=True,
        ))

    result.changes.sort(key=lambda c: (c.good_news, Severity.sort_key(c.severity)))
    return result


def _affected_asset(graph, cve_id: str) -> str:
    """Which of the owner's systems does this weakness sit on?"""
    try:
        for neighbour in graph.G.predecessors(cve_id):
            if _node_type(graph, neighbour) in ("service", "technology"):
                return friendly_name(graph, neighbour).split(" (")[0]
    except Exception:
        pass
    return "one of your systems"


def describe_risk_change(old: float, new: float, pct: float) -> str:
    """
    One sentence about how the exposure score moved.

    Percentages stop being meaningful when the starting score is near zero —
    "your exposure rose by 1720%" is technically true and completely useless to
    a business owner. Above a 200% swing this switches to words plus the two
    actual scores, which is what someone can act on.
    """
    direction = "risen" if pct > 0 else "dropped"

    if abs(pct) >= 200:
        return (
            f"Your overall exposure has {direction} sharply since the last check, "
            f"from {old:.0f} to {new:.0f} out of 100."
        )
    return (
        f"Your overall exposure has {direction} by {abs(pct):.0f}% since the last "
        f"check, from {old:.0f} to {new:.0f} out of 100."
    )


def _percent_change(old: float, new: float) -> float:
    """
    Percentage change from old to new.

    Going from zero to anything is treated as a 100% rise: there is no
    meaningful percentage there, but it is unambiguously worse.
    """
    if old <= 0:
        return 100.0 if new > 0 else 0.0
    return round(((new - old) / old) * 100.0, 1)


# ===========================================================================
# Comparing saved scan files
# ===========================================================================

def diff_scan_files(old_path: str, new_path: str) -> Optional[DiffResult]:
    """Compare two scan files on disk. Returns ``None`` if either cannot load."""
    old_graph = load_scan(old_path)
    new_graph = load_scan(new_path)
    if old_graph is None or new_graph is None:
        return None

    _old_time, domain = parse_scan_filename(new_path)
    result = diff_graphs(old_graph, new_graph, domain=domain)

    result.old_scan = old_path
    result.new_scan = new_path
    old_when, _ = parse_scan_filename(old_path)
    new_when, _ = parse_scan_filename(new_path)
    result.old_time = old_when.strftime("%d %b %Y at %H:%M") if old_when else ""
    result.new_time = new_when.strftime("%d %b %Y at %H:%M") if new_when else ""
    return result


def diff_latest_scans(scan_dir: str = "scans", domain: str = "") -> Optional[DiffResult]:
    """
    Compare the two most recent scans of a domain.

    Returns ``None`` when there is nothing to compare yet — the very first scan
    of a domain has no predecessor, which is normal and not an error.
    """
    scans = list_scans(scan_dir, domain)
    if len(scans) < 2:
        log.info("Only %d scan(s) on file for %s - nothing to compare yet.",
                 len(scans), domain or "any domain")
        return None
    return diff_scan_files(scans[-2], scans[-1])


# ===========================================================================
# Plain English rendering
# ===========================================================================

def format_diff_text(diff: DiffResult, width: int = 78) -> str:
    """
    Render the diff the way the business owner should read it, for example::

        2 new subdomains appeared since your last check:
          -> dev2.acme.com (WARNING: no HTTPS, publicly accessible)
          -> staging.acme.com (WARNING: this looks like a staging copy of your site)
        1 new critical weakness found on your email server.
    """
    rule = "=" * width
    out: list[str] = [rule, "  WHAT CHANGED SINCE YOUR LAST CHECK", rule, ""]

    if diff.domain:
        out.append(f"  Website : {diff.domain}")
    if diff.old_time and diff.new_time:
        out.append(f"  Compared: {diff.old_time}  ->  {diff.new_time}")
    out.append("")

    if not diff.has_changes:
        out.append(_wrap(
            "Nothing changed since the last check. Your attack surface looks exactly "
            "as it did before.", width, "  ", first="  "))
        out.append("")
        out.append(rule)
        return "\n".join(out)

    # --- grouped, most alarming first ------------------------------------
    groups: list[tuple[str, str, str]] = [
        ("new_subdomain",     "new address appeared since your last check",
                              "new addresses appeared since your last check"),
        ("new_port",          "new open door appeared on your servers",
                              "new open doors appeared on your servers"),
        ("new_cve",           "new security weakness found",
                              "new security weaknesses found"),
        ("new_service",       "new piece of software appeared",
                              "new pieces of software appeared"),
        ("removed_subdomain", "address disappeared",
                              "addresses disappeared"),
        ("risk_increase",     "your overall exposure went up",
                              "your overall exposure went up"),
    ]

    for kind, singular, plural in groups:
        changes = diff.of_kind(kind)
        if not changes:
            continue

        count   = len(changes)
        heading = singular if count == 1 else plural
        if kind == "risk_increase":
            out.append(f"  {_capitalise_first(heading)}:")
        else:
            out.append(f"  {count} {heading}:")

        for change in changes:
            out.append(_wrap(f"-> {change.plain}", width, "       ", first="    "))
            if change.warning:
                out.append(_wrap(f"WARNING: {change.warning}", width, "          ",
                                 first="       "))
        out.append("")

    good = diff.good_news
    if good:
        out.append("  GOOD NEWS:")
        for change in good:
            out.append(_wrap(f"-> {change.plain}", width, "       ", first="    "))
        out.append("")

    out.append(f"  Exposure score: {diff.old_risk_score:.0f} -> {diff.new_risk_score:.0f} "
               f"out of 100 ({_direction_word(diff.risk_change_pct)})")
    out.append("")
    out.append(rule)
    return "\n".join(out)


def _capitalise_first(text: str) -> str:
    text = str(text or "").strip()
    return text[0].upper() + text[1:] if text else text


def _direction_word(pct: float) -> str:
    """Short direction label, avoiding percentages that read as nonsense."""
    if pct >= 200:
        return "up sharply"
    if pct <= -200:
        return "down sharply"
    if pct > 0:
        return f"up {pct:.0f}%"
    if pct < 0:
        return f"down {abs(pct):.0f}%"
    return "unchanged"


# ===========================================================================
# CLI:  python -m monitor.diff_engine old.json new.json
# ===========================================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Explain what changed between two SurfaceWatch scans."
    )
    parser.add_argument("scan1", nargs="?", help="Older scan file")
    parser.add_argument("scan2", nargs="?", help="Newer scan file")
    parser.add_argument("--dir", default="scans",
                        help="Scan directory (used when no files are given)")
    parser.add_argument("--domain", default="",
                        help="Domain to compare the two latest scans of")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of text")
    args = parser.parse_args()

    if args.scan1 and args.scan2:
        outcome = diff_scan_files(args.scan1, args.scan2)
    else:
        outcome = diff_latest_scans(args.dir, args.domain)

    if outcome is None:
        raise SystemExit(
            "Nothing to compare. SurfaceWatch needs at least two scans of the same "
            "domain before it can tell you what changed."
        )

    if args.json:
        import json
        print(json.dumps(outcome.to_dict(), indent=2))
    else:
        print(format_diff_text(outcome))
