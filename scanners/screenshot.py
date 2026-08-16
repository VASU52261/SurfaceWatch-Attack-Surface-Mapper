"""
scanners/screenshot.py
----------------------
Takes a picture of every website the scan discovered.

This is the single feature that makes an attack surface report land with a
non-technical business owner. A list of hostnames means nothing to them. A
screenshot showing a forgotten 2019 staging copy of their shop, or a database
admin login page sitting wide open, needs no explanation at all - they look at
it and immediately understand.

Uses Selenium with headless Chrome. Screenshots are saved to
``static/screenshots/`` and the file path is recorded on the matching node in
the graph, so the web dashboard and the PDF report can show them.

Chrome is optional. If neither Chrome nor Chromium is installed, this logs one
clear line explaining how to install it and moves on - screenshots are a nice
extra, never a reason for a scan to fail.

Usage::

    from scanners.screenshot import capture_screenshots
    capture_screenshots(graph)                      # every live host
    capture_screenshots(graph, hosts=["shop.acme.com"])
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any, Optional

from graph.builder import AttackSurfaceGraph, NodeType

log = logging.getLogger(__name__)

DEFAULT_OUTPUT_DIR = os.path.join("static", "screenshots")
PAGE_LOAD_TIMEOUT  = 10        # seconds per page, as specified
WINDOW_SIZE        = (1366, 768)
MAX_HOSTS          = 25        # safety cap for brute-forced subdomain lists


# ===========================================================================
# Results
# ===========================================================================

@dataclass
class ScreenshotResult:
    """The outcome of trying to photograph one host."""

    host: str
    url: str = ""
    path: str = ""
    ok: bool = False
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "host":  self.host,
            "url":   self.url,
            "path":  self.path,
            "ok":    self.ok,
            "error": self.error,
        }


# ===========================================================================
# Filenames
# ===========================================================================

def screenshot_filename(host: str) -> str:
    """
    Turn a hostname into a safe filename: ``shop.acme.com`` -> ``shop.acme.com.png``.

    Anything that is not a letter, digit, dot or dash is replaced, so a
    malformed hostname can never write outside the screenshots directory.
    """
    safe = re.sub(r"[^A-Za-z0-9.\-]", "_", str(host).strip().lower())
    safe = safe.strip("._-") or "unknown"
    return f"{safe}.png"


def ensure_output_dir(output_dir: str = DEFAULT_OUTPUT_DIR) -> str:
    """Create the screenshots directory if needed. Returns the path."""
    try:
        os.makedirs(output_dir, exist_ok=True)
    except OSError as exc:
        log.error("Could not create screenshot directory %s: %s", output_dir, exc)
    return output_dir


# ===========================================================================
# The browser
# ===========================================================================

def _build_driver(timeout: int = PAGE_LOAD_TIMEOUT):
    """
    Start a headless Chrome.

    Returns ``None`` (with a helpful log line) rather than raising when
    Selenium or Chrome is unavailable, so a machine without Chrome still runs
    every other scanner normally.
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        log.warning(
            "Screenshots skipped - Selenium is not installed. "
            "Install it with:  pip install selenium"
        )
        return None

    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")              # required inside Docker
    options.add_argument("--disable-dev-shm-usage")   # avoids crashes in containers
    options.add_argument(f"--window-size={WINDOW_SIZE[0]},{WINDOW_SIZE[1]}")
    options.add_argument("--ignore-certificate-errors")  # expired certs are common
    options.add_argument("--log-level=3")
    options.set_capability("acceptInsecureCerts", True)

    try:
        driver = webdriver.Chrome(options=options)
    except Exception as exc:
        log.warning(
            "Screenshots skipped - could not start headless Chrome (%s). "
            "Install Google Chrome or Chromium to enable screenshots.",
            str(exc).splitlines()[0][:160],
        )
        return None

    try:
        driver.set_page_load_timeout(timeout)
        driver.implicitly_wait(1)
    except Exception:
        pass

    return driver


def is_available() -> bool:
    """
    True when screenshots can actually be taken on this machine.

    Useful for the CLI and the web dashboard, which can then say "install
    Chrome to enable screenshots" instead of silently showing nothing.
    """
    driver = _build_driver()
    if driver is None:
        return False
    try:
        driver.quit()
    except Exception:
        pass
    return True


# ===========================================================================
# Capturing
# ===========================================================================

def capture_host(host: str, driver, output_dir: str = DEFAULT_OUTPUT_DIR,
                 timeout: int = PAGE_LOAD_TIMEOUT) -> ScreenshotResult:
    """
    Photograph one host, trying HTTPS first and then plain HTTP.

    A timeout is a normal result, not an error worth stopping for: plenty of
    discovered subdomains point at hosts that no longer answer.
    """
    result = ScreenshotResult(host=host)
    ensure_output_dir(output_dir)
    path = os.path.join(output_dir, screenshot_filename(host))

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            driver.set_page_load_timeout(timeout)
            driver.get(url)
        except Exception as exc:
            # Includes TimeoutException; try the next scheme.
            result.error = f"{scheme}: {type(exc).__name__}"
            log.debug("Could not load %s: %s", url, exc)
            continue

        try:
            if driver.save_screenshot(path):
                result.url  = url
                result.path = path
                result.ok   = True
                result.error = ""
                log.info("Screenshot saved: %s -> %s", url, path)
                return result
            result.error = "the browser returned no image"
        except Exception as exc:
            result.error = str(exc)[:160]
            log.debug("Could not save a screenshot of %s: %s", url, exc)

    if not result.ok:
        log.info("No screenshot for %s (%s)", host, result.error or "no response")
    return result


def _hosts_to_capture(graph: AttackSurfaceGraph, hosts: Optional[list[str]]) -> list[str]:
    """Default to the domain plus every exposed subdomain."""
    if hosts:
        return list(hosts)

    found = graph.nodes_by_type(NodeType.DOMAIN) + graph.nodes_by_type(NodeType.SUBDOMAIN)
    return [h for h in found if graph.G.nodes[h].get("exposed", True)]


def capture_screenshots(graph: AttackSurfaceGraph,
                        hosts: Optional[list[str]] = None,
                        output_dir: str = DEFAULT_OUTPUT_DIR,
                        timeout: int = PAGE_LOAD_TIMEOUT,
                        max_hosts: int = MAX_HOSTS) -> dict[str, ScreenshotResult]:
    """
    Screenshot every live host in the graph and record the paths on the nodes.

    The saved file path is stored as ``meta["screenshot"]`` on the matching
    domain or subdomain node, so the frontend and the PDF report can display it
    without re-running anything.

    One browser is started for the whole run rather than one per host, which is
    dramatically faster. If the browser cannot start at all, an empty result is
    returned and the scan continues.
    """
    targets = _hosts_to_capture(graph, hosts)[:max_hosts]
    if not targets:
        log.warning("No hosts to screenshot.")
        return {}

    driver = _build_driver(timeout=timeout)
    if driver is None:
        return {}

    log.info("Taking screenshots of %d host(s) ...", len(targets))
    results: dict[str, ScreenshotResult] = {}

    try:
        for host in targets:
            try:
                result = capture_host(host, driver, output_dir=output_dir,
                                      timeout=timeout)
            except Exception as exc:
                log.error("Screenshot failed for %s: %s", host, exc)
                result = ScreenshotResult(host=host, error=str(exc)[:160])

            results[host] = result

            if result.ok:
                try:
                    _record_on_graph(graph, host, result)
                except Exception as exc:
                    log.error("Could not record the screenshot for %s: %s", host, exc)
    finally:
        try:
            driver.quit()
        except Exception:
            pass

    taken = sum(1 for r in results.values() if r.ok)
    log.info("Screenshots complete: %d of %d host(s) photographed.",
             taken, len(results))
    return results


def _record_on_graph(graph: AttackSurfaceGraph, host: str,
                     result: ScreenshotResult) -> None:
    """Store the screenshot path in the node's metadata."""
    if host not in graph.G:
        return

    node = graph.G.nodes[host]
    meta = node.get("meta") if isinstance(node.get("meta"), dict) else {}

    # Store a forward-slash path: it goes straight into an HTML img src, and
    # Windows backslashes would break that.
    meta["screenshot"]     = result.path.replace("\\", "/")
    meta["screenshot_url"] = result.url
    meta["is_live"]        = True

    node["meta"] = meta


def screenshots_in_graph(graph: AttackSurfaceGraph) -> dict[str, str]:
    """
    Every screenshot recorded in the graph, as ``{hostname: image path}``.

    Used by the PDF report and the web dashboard.
    """
    found: dict[str, str] = {}

    for node_id in (graph.nodes_by_type(NodeType.DOMAIN)
                    + graph.nodes_by_type(NodeType.SUBDOMAIN)):
        meta = graph.G.nodes[node_id].get("meta")
        if isinstance(meta, dict) and meta.get("screenshot"):
            found[node_id] = meta["screenshot"]

    return found


# ===========================================================================
# CLI:  python -m scanners.screenshot example.com
# ===========================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(
        description="Take screenshots of one or more websites."
    )
    parser.add_argument("host", nargs="*", help="Hostname(s) to photograph")
    parser.add_argument("--out", default=DEFAULT_OUTPUT_DIR,
                        help=f"Where to save images (default: {DEFAULT_OUTPUT_DIR})")
    parser.add_argument("--timeout", type=int, default=PAGE_LOAD_TIMEOUT,
                        help="Seconds to wait per page (default: 10)")
    parser.add_argument("--check", action="store_true",
                        help="Only report whether screenshots are available here")
    args = parser.parse_args()

    if args.check:
        if is_available():
            print("Screenshots are available - headless Chrome started successfully.")
        else:
            print("Screenshots are NOT available. Install Google Chrome or Chromium.")
        raise SystemExit(0)

    if not args.host:
        raise SystemExit("Give at least one hostname, or use --check.")

    browser = _build_driver(timeout=args.timeout)
    if browser is None:
        raise SystemExit("Could not start headless Chrome.")

    try:
        for hostname in args.host:
            outcome = capture_host(hostname, browser, output_dir=args.out,
                                   timeout=args.timeout)
            if outcome.ok:
                print(f"  {hostname}: saved to {outcome.path}")
            else:
                print(f"  {hostname}: no screenshot ({outcome.error or 'no response'})")
    finally:
        try:
            browser.quit()
        except Exception:
            pass
