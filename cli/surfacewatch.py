"""
cli/surfacewatch.py
---------------
The SurfaceWatch command line tool.

Four commands cover the whole product:

    surfacewatch scan    --target acme.com --output report.pdf
    surfacewatch monitor --target acme.com --interval 24h
    surfacewatch report  --scan-file scan.json --format pdf
    surfacewatch diff    --scan1 old.json --scan2 new.json

The terminal output is written for the same person as the reports: someone who
runs a business and wants a straight answer. Progress is shown while scans run
(they take minutes, and silence looks like a hang), findings are colour coded
by severity, and every command ends by saying what to do next.

Run from the project root::

    python -m cli.surfacewatch --help
    python -m cli.surfacewatch scan --target example.com
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
from datetime import datetime
from typing import Optional

import click

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

console = Console()

VERSION = "1.0.0"

#: Terminal colours, matching the severity colours used in the PDF and emails.
SEVERITY_STYLE = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}

SEVERITY_COLOUR = {
    "CRITICAL": "red",
    "HIGH":     "dark_orange",
    "MEDIUM":   "yellow",
    "LOW":      "green",
}


# ===========================================================================
# Helpers
# ===========================================================================

def _quiet_logging(verbose: bool = False) -> None:
    """
    Keep the scanners' log chatter out of the way unless asked for.

    The libraries log at INFO by default, which would bury the formatted
    output the user is meant to read.
    """
    logging.basicConfig(
        level=logging.INFO if verbose else logging.WARNING,
        format="%(levelname)s | %(message)s",
    )


def parse_interval(value: str) -> float:
    """
    Turn ``24h``, ``30m``, ``2d`` or a bare number into hours.

    A bare number is read as hours, since that is what ``--interval 24`` means
    to anyone typing it.
    """
    text = str(value or "").strip().lower()
    if not text:
        return 24.0

    match = re.fullmatch(r"(\d+(?:\.\d+)?)\s*([smhd]?)", text)
    if not match:
        raise click.BadParameter(
            f"Could not understand the interval '{value}'. "
            f"Use something like 24h, 30m, 2d or just 24."
        )

    amount = float(match.group(1))
    unit   = match.group(2) or "h"
    return {"s": amount / 3600.0, "m": amount / 60.0,
            "h": amount, "d": amount * 24.0}[unit]


def _banner() -> None:
    console.print(Panel.fit(
        Text.assemble(
            ("SurfaceWatch", "bold cyan"),
            ("  Attack Surface Monitor for small businesses", "dim"),
        ),
        border_style="cyan",
    ))


def _severity_text(severity: str) -> Text:
    return Text(severity, style=SEVERITY_STYLE.get(severity, "white"))


def _print_summary(report: dict) -> None:
    """The headline block shown after a scan or a report."""
    level  = report.get("overall_risk", "LOW")
    score  = float(report.get("risk_score", 0) or 0)
    colour = SEVERITY_COLOUR.get(level, "white")

    console.print()
    console.print(Panel(
        Text.assemble(
            (f"{level}\n", f"bold {colour}"),
            (report.get("headline", ""), ""),
        ),
        title="[bold]Overall risk[/bold]",
        border_style=colour,
    ))

    counts = report.get("severity_counts", {})
    table  = Table(show_header=True, header_style="bold", box=None, pad_edge=False)
    table.add_column("Urgent",   justify="center")
    table.add_column("Serious",  justify="center")
    table.add_column("Moderate", justify="center")
    table.add_column("Minor",    justify="center")
    table.add_column("Exposure", justify="center")
    table.add_row(
        f"[red]{counts.get('CRITICAL', 0)}[/red]",
        f"[dark_orange]{counts.get('HIGH', 0)}[/dark_orange]",
        f"[yellow]{counts.get('MEDIUM', 0)}[/yellow]",
        f"[green]{counts.get('LOW', 0)}[/green]",
        f"[{colour}]{score:.0f}/100[/{colour}]",
    )
    console.print(table)

    actions = report.get("top_actions") or []
    if actions:
        console.print("\n[bold]The three things to fix first[/bold]")
        for index, action in enumerate(actions, 1):
            console.print(f"  [cyan]{index}.[/cyan] {action}")


def _print_findings(report: dict, limit: int = 10) -> None:
    """A compact table of findings, worst first."""
    findings = report.get("findings") or []
    if not findings:
        console.print("\n[green]Nothing needs your attention right now.[/green]")
        return

    table = Table(title=f"\nWhat we found ({len(findings)})",
                  header_style="bold", title_justify="left", expand=True)
    table.add_column("Severity", width=10)
    table.add_column("What is exposed")
    table.add_column("What to do")

    for finding in findings[:limit]:
        table.add_row(
            _severity_text(finding.get("severity", "LOW")),
            finding.get("what_is_exposed", ""),
            finding.get("recommended_action", ""),
        )
    console.print(table)

    if len(findings) > limit:
        console.print(f"[dim]  ... and {len(findings) - limit} more. "
                      f"Produce a full report to see them all.[/dim]")


def _load_graph(path: str):
    """Load a saved scan, exiting cleanly with a readable message on failure."""
    from graph.builder import AttackSurfaceGraph
    try:
        return AttackSurfaceGraph.load(path)
    except FileNotFoundError:
        console.print(f"[red]Could not find the scan file:[/red] {path}")
        sys.exit(1)
    except Exception as exc:
        console.print(f"[red]Could not read {path}:[/red] {exc}")
        sys.exit(1)


# ===========================================================================
# CLI group
# ===========================================================================

@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(VERSION, prog_name="SurfaceWatch")
def cli() -> None:
    """
    SurfaceWatch - find out what a criminal can see of your business.

    Free and open source. No account, no subscription, no paid API needed.
    """


# ===========================================================================
# scan
# ===========================================================================

@cli.command()
@click.option("--target", "-t", required=True, help="Domain to scan, e.g. acme.com")
@click.option("--output", "-o", default="", help="Write a report here (.pdf, .html or .json)")
@click.option("--ports", default="21,22,23,25,53,80,443,445,3306,3389,5432,8080,8443",
              help="Ports to check")
@click.option("--skip-cve", is_flag=True, help="Skip the CVE lookup (much faster)")
@click.option("--screenshots/--no-screenshots", default=False,
              help="Photograph each website (needs Chrome)")
@click.option("--save-scan", default="", help="Also save the raw scan JSON here")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed scanner output")
def scan(target: str, output: str, ports: str, skip_cve: bool,
         screenshots: bool, save_scan: str, verbose: bool) -> None:
    """
    Scan a domain and tell you what is exposed.

    Example:

        surfacewatch scan --target acme.com --output report.pdf
    """
    _quiet_logging(verbose)
    _banner()

    console.print(f"\nChecking [bold cyan]{target}[/bold cyan] "
                  f"the way an outsider would see it.\n")

    from graph.builder import AttackSurfaceGraph
    from reports.plain_english import generate_report
    from scanners.subdomain_enum import enumerate_subdomains
    from scanners.port_scanner import scan_ports

    graph = AttackSurfaceGraph(target=target)
    graph.add_domain(target)
    subdomains: list[str] = []

    steps = [
        ("Looking for web addresses you own", "subdomains"),
        ("Checking which doors are open",     "ports"),
        ("Identifying the software you run",  "tech"),
    ]
    if not skip_cve:
        steps.append(("Looking up known weaknesses", "cve"))
    if screenshots:
        steps.append(("Photographing your websites", "shots"))

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=24),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Starting...", total=len(steps))

        for description, stage in steps:
            progress.update(task, description=description)

            try:
                if stage == "subdomains":
                    subdomains = enumerate_subdomains(graph, target) or []

                elif stage == "ports":
                    scan_ports(graph, target, ports=ports)
                    for subdomain in subdomains[:3]:
                        scan_ports(graph, subdomain, ports=ports)

                elif stage == "tech":
                    from scanners.tech_detect import detect_technologies
                    detect_technologies(graph)
                    from scanners.shodan_scanner import enrich_graph_with_shodan
                    enrich_graph_with_shodan(graph)

                elif stage == "cve":
                    from scanners.cve_lookup import lookup_cves_for_graph
                    lookup_cves_for_graph(graph)

                elif stage == "shots":
                    from scanners.screenshot import capture_screenshots
                    capture_screenshots(graph)

            except Exception as exc:
                # One failed stage must not lose the work already done.
                console.print(f"  [yellow]Could not finish '{description}': {exc}[/yellow]")

            progress.advance(task)

    console.print(f"\n[green]Scan finished.[/green] Found "
                  f"{graph.G.number_of_nodes()} things belonging to {target}.")

    report = generate_report(graph)
    _print_summary(report)
    _print_findings(report)

    if save_scan:
        try:
            graph.save(save_scan)
            console.print(f"\n[dim]Raw scan saved to {save_scan}[/dim]")
        except Exception as exc:
            console.print(f"[yellow]Could not save the scan: {exc}[/yellow]")

    if output:
        _write_report(graph, output, report)

    console.print("\n[bold]What next?[/bold]")
    console.print("  Work down the list above, most urgent first.")
    console.print(f"  To be told when anything changes:  "
                  f"[cyan]surfacewatch monitor --target {target}[/cyan]")


# ===========================================================================
# monitor
# ===========================================================================

@cli.command()
@click.option("--target", "-t", multiple=True, required=True,
              help="Domain to watch (repeat for several)")
@click.option("--interval", "-i", default="24h",
              help="How often to rescan: 24h, 12h, 30m, 2d")
@click.option("--scan-dir", default="scans", help="Where scan history is kept")
@click.option("--skip-cve", is_flag=True, help="Skip the CVE lookup on each run")
@click.option("--no-alerts", is_flag=True, help="Do not send alert emails")
@click.option("--once", is_flag=True, help="Run one scan now and exit")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed scanner output")
def monitor(target: tuple, interval: str, scan_dir: str, skip_cve: bool,
            no_alerts: bool, once: bool, verbose: bool) -> None:
    """
    Watch one or more domains and alert you when something changes.

    Example:

        surfacewatch monitor --target acme.com --interval 24h
    """
    _quiet_logging(verbose)
    _banner()

    hours   = parse_interval(interval)
    domains = list(target)

    from monitor.scheduler import ScanScheduler

    scheduler = ScanScheduler(
        scan_dir=scan_dir,
        interval_hours=hours,
        send_alerts=not no_alerts,
    )
    for domain in domains:
        scheduler.add_target(domain, skip_cve=skip_cve, interval_hours=hours)

    if once:
        console.print(f"\nRunning one scan of {len(domains)} domain(s) now.\n")
        for domain in domains:
            outcome = scheduler.scan_once(domain)
            if outcome.get("error"):
                console.print(f"[red]{domain}: {outcome['error']}[/red]")
            else:
                console.print(f"[green]{domain}:[/green] saved to "
                              f"{outcome.get('scan_file', '?')}, "
                              f"{outcome.get('changes', 0)} change(s) since last time")
        return

    table = Table(title="Now watching", header_style="bold")
    table.add_column("Domain")
    table.add_column("Checked every")
    table.add_column("Email alerts")
    for domain in domains:
        table.add_row(domain, f"{hours:g} hours",
                      "off" if no_alerts else "on")
    console.print(table)

    if not scheduler.start(run_now=True):
        console.print("[red]Could not start monitoring.[/red] "
                      "Install APScheduler with: pip install apscheduler")
        sys.exit(1)

    console.print(f"\n[green]Monitoring is running.[/green] "
                  f"Scans are saved to [cyan]{scan_dir}/[/cyan]")
    if not no_alerts:
        console.print("[dim]You will be emailed only when something needs you. "
                      "Set SMTP details in .env to receive alerts.[/dim]")
    console.print("[dim]Press Ctrl+C to stop.[/dim]\n")

    import time
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        console.print("\n[yellow]Monitoring stopped.[/yellow]")


# ===========================================================================
# report
# ===========================================================================

@cli.command()
@click.option("--scan-file", "-s", required=True, help="A saved scan JSON file")
@click.option("--format", "-f", "output_format",
              type=click.Choice(["pdf", "html", "json"], case_sensitive=False),
              default="pdf", help="What kind of report to produce")
@click.option("--output", "-o", default="", help="Where to write it")
@click.option("--logo", default="", help="Optional logo image for the PDF")
@click.option("--show", is_flag=True, help="Also print the findings here")
def report(scan_file: str, output_format: str, output: str,
           logo: str, show: bool) -> None:
    """
    Turn a saved scan into a report.

    Example:

        surfacewatch report --scan-file scan.json --format pdf
    """
    _quiet_logging()
    graph = _load_graph(scan_file)

    from reports.plain_english import generate_report
    scan_report = generate_report(graph)

    if show:
        _print_summary(scan_report)
        _print_findings(scan_report, limit=25)

    output_format = output_format.lower()
    if not output:
        stem = os.path.splitext(os.path.basename(scan_file))[0]
        output = f"{stem}_report.{output_format}"

    written = _write_report(graph, output, scan_report,
                            output_format=output_format,
                            logo=logo or None)
    if not written:
        sys.exit(1)


def _write_report(graph, output: str, scan_report: dict,
                  output_format: Optional[str] = None,
                  logo: Optional[str] = None) -> Optional[str]:
    """Write a report in whichever format the filename or flag asks for."""
    output_format = (output_format
                     or os.path.splitext(output)[1].lstrip(".").lower()
                     or "pdf")

    try:
        if output_format == "json":
            from reports.attack_story import generate_story_report
            payload = dict(scan_report)
            payload["attack_paths"] = generate_story_report(graph, top_n=3)

            directory = os.path.dirname(os.path.abspath(output))
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(output, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2)
            written = output

        elif output_format == "html":
            from reports.html_report import generate_html
            written = generate_html(graph, output, report=scan_report)

        elif output_format == "pdf":
            from reports.pdf_generator import generate_pdf
            written = generate_pdf(graph, output, logo_path=logo, report=scan_report)

        else:
            console.print(f"[red]Unknown report format:[/red] {output_format}")
            return None

    except Exception as exc:
        console.print(f"[red]Could not create the report:[/red] {exc}")
        return None

    if not written:
        console.print("[red]The report could not be created.[/red] "
                      "If this is a PDF, check that reportlab is installed: "
                      "pip install reportlab")
        return None

    console.print(f"\n[green]Report saved:[/green] [bold]{written}[/bold]")
    return written


# ===========================================================================
# diff
# ===========================================================================

@cli.command()
@click.option("--scan1", required=False, help="The older scan file")
@click.option("--scan2", required=False, help="The newer scan file")
@click.option("--scan-dir", default="scans",
              help="Compare the two latest scans in this folder instead")
@click.option("--domain", default="", help="Which domain to compare")
@click.option("--json", "as_json", is_flag=True, help="Print JSON instead")
def diff(scan1: str, scan2: str, scan_dir: str, domain: str, as_json: bool) -> None:
    """
    Show what changed between two scans.

    Example:

        surfacewatch diff --scan1 monday.json --scan2 friday.json
    """
    _quiet_logging()

    from monitor.diff_engine import diff_latest_scans, diff_scan_files

    if scan1 and scan2:
        result = diff_scan_files(scan1, scan2)
    else:
        result = diff_latest_scans(scan_dir, domain)

    if result is None:
        console.print(
            "[yellow]Nothing to compare.[/yellow] SurfaceWatch needs two scans of the "
            "same domain before it can tell you what changed.\n"
            "Run a scan today and another tomorrow, or use "
            "[cyan]surfacewatch monitor[/cyan] to do it automatically."
        )
        sys.exit(1)

    if as_json:
        console.print_json(json.dumps(result.to_dict()))
        return

    _banner()
    console.print(f"\n[bold]{result.summary_line}[/bold]")
    if result.old_time and result.new_time:
        console.print(f"[dim]{result.old_time}  ->  {result.new_time}[/dim]")

    if not result.has_changes:
        console.print("\n[green]Nothing changed. Your attack surface looks "
                      "exactly as it did before.[/green]")
        return

    table = Table(title="\nWhat changed", header_style="bold",
                  title_justify="left", expand=True)
    table.add_column("Severity", width=10)
    table.add_column("What happened")
    table.add_column("Why it matters")

    for change in result.bad_news:
        table.add_row(_severity_text(change.severity), change.plain, change.warning)
    console.print(table)

    good = result.good_news
    if good:
        console.print("\n[bold green]Good news[/bold green]")
        for change in good:
            console.print(f"  [green]+[/green] {change.plain}")

    direction = ("up" if result.risk_change_pct > 0
                 else "down" if result.risk_change_pct < 0 else "unchanged")
    colour = "red" if result.risk_change_pct > 0 else "green"
    console.print(f"\nExposure score: {result.old_risk_score:.0f} -> "
                  f"[{colour}]{result.new_risk_score:.0f}[/{colour}] out of 100 "
                  f"({direction})")


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> None:
    """Console entry point."""
    try:
        cli()
    except KeyboardInterrupt:
        console.print("\n[yellow]Stopped.[/yellow]")
        sys.exit(130)


if __name__ == "__main__":
    main()
