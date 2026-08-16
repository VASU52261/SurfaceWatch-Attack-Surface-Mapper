"""
scanners/tech_detect.py
-----------------------
Works out what software a website is built with, by looking at what it tells
the world for free.

Knowing that a site runs WordPress 5.2 or PHP 7.1 matters, because that is
exactly how an attacker decides which attack to try first. It is also how
SurfaceWatch spots software that is years out of date and quietly missing security
fixes.

Four signals are used, all of them passive - this only makes ordinary web
requests, the same as any visitor's browser:

    1. HTTP response headers   (Server, X-Powered-By, X-Generator, ...)
    2. HTML content            (meta generator tags, script and link sources)
    3. Cookie names            (wordpress_logged_in, PHPSESSID, ...)
    4. Well-known file paths   (/wp-login.php means WordPress)

Everything found is added to the graph as technology nodes linked to the
subdomain it was found on, so the reporting and attack path engines pick it up
automatically. Versions that are known to be old are flagged in plain English.

Usage::

    from scanners.tech_detect import detect_technologies
    detect_technologies(graph)                      # every subdomain
    detect_technologies(graph, hosts=["shop.acme.com"])
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Optional

import requests

from graph.builder import AttackSurfaceGraph, EdgeData, EdgeType, NodeData, NodeType

log = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10          # seconds per request
USER_AGENT = "Mozilla/5.0 (compatible; SurfaceWatch/1.0; +https://github.com/surfacewatch)"

#: Only fetch these extra paths when the front page hints at them, to keep the
#: scan polite - a handful of requests per host, not hundreds.
MAX_PROBE_PATHS = 6


# ===========================================================================
# Signatures
# ===========================================================================

#: Response header -> how to read it.
#: (header name, regex with an optional "version" group, technology name)
HEADER_SIGNATURES: list[tuple[str, str, str]] = [
    ("server",          r"nginx(?:/(?P<version>[\d.]+))?",            "nginx"),
    ("server",          r"apache(?:/(?P<version>[\d.]+))?",           "Apache"),
    ("server",          r"microsoft-iis(?:/(?P<version>[\d.]+))?",    "Microsoft IIS"),
    ("server",          r"litespeed(?:/(?P<version>[\d.]+))?",        "LiteSpeed"),
    ("server",          r"openresty(?:/(?P<version>[\d.]+))?",        "OpenResty"),
    ("server",          r"cloudflare",                                "Cloudflare"),
    ("server",          r"gunicorn(?:/(?P<version>[\d.]+))?",         "Gunicorn"),
    ("server",          r"werkzeug(?:/(?P<version>[\d.]+))?",         "Werkzeug"),
    ("x-powered-by",    r"php(?:/(?P<version>[\d.]+))?",              "PHP"),
    ("x-powered-by",    r"asp\.net",                                  "ASP.NET"),
    ("x-powered-by",    r"express",                                   "Express"),
    ("x-powered-by",    r"next\.js",                                  "Next.js"),
    ("x-aspnet-version", r"(?P<version>[\d.]+)",                      "ASP.NET"),
    ("x-generator",     r"drupal\s*(?P<version>[\d.]+)?",             "Drupal"),
    ("x-drupal-cache",  r".",                                         "Drupal"),
    ("x-shopify-stage", r".",                                         "Shopify"),
    ("x-wix-request-id", r".",                                        "Wix"),
]

#: Cookie name (lowercase substring) -> technology it gives away.
COOKIE_SIGNATURES: dict[str, str] = {
    "wordpress_":     "WordPress",
    "wp-settings":    "WordPress",
    "phpsessid":      "PHP",
    "jsessionid":     "Java",
    "asp.net_session": "ASP.NET",
    "aspsessionid":   "ASP.NET",
    "laravel_session": "Laravel",
    "ci_session":     "CodeIgniter",
    "django":         "Django",
    "csrftoken":      "Django",
    "_shopify":       "Shopify",
    "sessionid":      "",          # too generic to name - ignored
}

#: Fragments in HTML (script sources, link hrefs, inline markers).
HTML_SIGNATURES: list[tuple[str, str]] = [
    (r"/wp-content/",                    "WordPress"),
    (r"/wp-includes/",                   "WordPress"),
    (r"/sites/default/files/",           "Drupal"),
    (r"/media/jui/",                     "Joomla"),
    (r"/templates/[^/]+/",               "Joomla"),
    (r"jquery[.-](?P<version>[\d.]+)",   "jQuery"),
    (r"bootstrap[.-](?P<version>[\d.]+)", "Bootstrap"),
    (r"react(?:-dom)?[.-](?P<version>[\d.]+)", "React"),
    (r"angular[.-](?P<version>[\d.]+)",  "Angular"),
    (r"vue[.-](?P<version>[\d.]+)",      "Vue.js",),
    (r"cdn\.shopify\.com",               "Shopify"),
    (r"static\.parastorage\.com",        "Wix"),
    (r"squarespace",                     "Squarespace"),
    (r"__NEXT_DATA__",                   "Next.js"),
    (r"/_nuxt/",                         "Nuxt.js"),
    (r"csrfmiddlewaretoken",             "Django"),
    (r"cdnjs\.cloudflare\.com",          "Cloudflare CDN"),
    (r"googletagmanager\.com",           "Google Tag Manager"),
]

#: Paths that confirm a technology when they exist.
#: (path, technology, what finding it means in plain English)
PATH_SIGNATURES: list[tuple[str, str, str]] = [
    ("/wp-login.php",       "WordPress",   "the WordPress login page is public"),
    ("/wp-admin/",          "WordPress",   "the WordPress admin area is reachable"),
    ("/administrator/",     "Joomla",      "the Joomla admin area is reachable"),
    ("/user/login",         "Drupal",      "the Drupal login page is public"),
    ("/phpmyadmin/",        "phpMyAdmin",  "a database admin tool is published on the internet"),
    ("/.git/config",        "Git",         "your source code repository is downloadable"),
    ("/.env",               "Env file",    "a configuration file that usually holds passwords is downloadable"),
    ("/server-status",      "Apache",      "an internal server status page is public"),
]

#: Newest version we know about, used to flag software that is out of date.
#: Only the major line matters here - this is a "you are years behind" check,
#: not a substitute for the CVE lookup.
LATEST_KNOWN_MAJOR: dict[str, float] = {
    "WordPress":     6.0,
    "PHP":           8.0,
    "Drupal":       10.0,
    "Joomla":        5.0,
    "jQuery":        3.0,
    "Bootstrap":     5.0,
    "nginx":         1.24,
    "Apache":        2.4,
    "Microsoft IIS": 10.0,
    "OpenSSL":       3.0,
}

#: Software where running an old version is especially dangerous.
HIGH_RISK_IF_OUTDATED = {"WordPress", "PHP", "Drupal", "Joomla", "OpenSSL"}


# ===========================================================================
# Results
# ===========================================================================

@dataclass
class DetectedTech:
    """One piece of software found on a host."""

    name: str
    version: str = ""
    source: str = ""              # how we spotted it (header, cookie, html, path)
    outdated: bool = False
    concern: str = ""             # plain English worry, if any
    evidence: str = ""            # the technical detail, for an IT person

    def to_dict(self) -> dict:
        return {
            "name":     self.name,
            "version":  self.version,
            "source":   self.source,
            "outdated": self.outdated,
            "concern":  self.concern,
            "evidence": self.evidence,
        }


@dataclass
class HostTechReport:
    """Everything detected on one hostname."""

    host: str
    url: str = ""
    status_code: int = 0
    technologies: list[DetectedTech] = field(default_factory=list)
    error: str = ""

    @property
    def ok(self) -> bool:
        return bool(self.technologies) and not self.error

    def to_dict(self) -> dict:
        return {
            "host":         self.host,
            "url":          self.url,
            "status_code":  self.status_code,
            "technologies": [t.to_dict() for t in self.technologies],
            "error":        self.error,
        }


# ===========================================================================
# Version helpers
# ===========================================================================

def _clean_version(version: str) -> str:
    """
    Tidy a version scraped out of a filename.

    A pattern like ``jquery-1.12.4.min.js`` yields ``"1.12.4."`` because the
    dot before ``min`` is part of the match, so trailing separators are
    stripped here rather than in every signature.
    """
    return str(version or "").strip().strip(".-_")


def _major_version(version: str) -> Optional[float]:
    """``"5.7.20"`` -> ``5.7``. Returns None when there is no usable number."""
    match = re.match(r"(\d+)(?:\.(\d+))?", str(version or ""))
    if not match:
        return None
    try:
        major = match.group(1)
        minor = match.group(2) or "0"
        return float(f"{major}.{minor}")
    except (TypeError, ValueError):
        return None


def check_outdated(name: str, version: str) -> tuple[bool, str]:
    """
    Is this version old enough to worry about?

    Returns ``(is_outdated, plain English concern)``. Deliberately
    conservative: we only flag software we have a reference version for, so a
    business owner is never told to panic about something we cannot judge.
    """
    if not version:
        return False, ""

    latest = LATEST_KNOWN_MAJOR.get(name)
    found  = _major_version(version)
    if latest is None or found is None or found >= latest:
        return False, ""

    if name in HIGH_RISK_IF_OUTDATED:
        return True, (
            f"You are running {name} {version}, which is several versions behind. "
            f"Old versions stop receiving security fixes, so weaknesses found "
            f"after it was retired are never repaired."
        )
    return True, (
        f"{name} {version} is out of date. Updating it is routine maintenance "
        f"and closes off known problems."
    )


# ===========================================================================
# Detection
# ===========================================================================

def _fetch(url: str, session: requests.Session,
           allow_redirects: bool = True) -> Optional[requests.Response]:
    """Make one polite web request, returning None on any failure."""
    try:
        return session.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=allow_redirects,
            headers={"User-Agent": USER_AGENT},
            verify=True,
        )
    except requests.exceptions.SSLError:
        # A broken certificate is worth knowing about but is reported
        # elsewhere; retry without verification so detection still works.
        try:
            return session.get(url, timeout=REQUEST_TIMEOUT,
                               allow_redirects=allow_redirects,
                               headers={"User-Agent": USER_AGENT}, verify=False)
        except requests.RequestException:
            return None
    except requests.RequestException:
        return None


def _from_headers(response: requests.Response) -> list[DetectedTech]:
    """Read the response headers, which are the most reliable signal."""
    found: list[DetectedTech] = []
    headers = {k.lower(): str(v) for k, v in response.headers.items()}

    for header_name, pattern, tech_name in HEADER_SIGNATURES:
        value = headers.get(header_name)
        if not value:
            continue

        match = re.search(pattern, value, re.IGNORECASE)
        if not match:
            continue

        version = ""
        if "version" in (match.groupdict() or {}):
            version = _clean_version(match.group("version"))

        found.append(DetectedTech(
            name=tech_name, version=version, source="response header",
            evidence=f"{header_name}: {value[:120]}",
        ))

    return found


def _from_cookies(response: requests.Response) -> list[DetectedTech]:
    """Cookie names often give away the framework behind a site."""
    found: list[DetectedTech] = []

    for cookie_name in response.cookies.keys():
        lowered = str(cookie_name).lower()
        for fragment, tech_name in COOKIE_SIGNATURES.items():
            if tech_name and fragment in lowered:
                found.append(DetectedTech(
                    name=tech_name, source="cookie",
                    evidence=f"cookie named {cookie_name}",
                ))
    return found


def _from_html(html_text: str) -> list[DetectedTech]:
    """Meta generator tags, script sources and other markers in the page."""
    found: list[DetectedTech] = []
    if not html_text:
        return found

    # <meta name="generator" content="WordPress 5.2.1">
    for match in re.finditer(
        r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""",
        html_text, re.IGNORECASE,
    ):
        content = match.group(1).strip()
        name_match = re.match(r"([A-Za-z][A-Za-z0-9 .!_-]*?)\s*([\d][\d.]*)?$", content)
        if name_match:
            found.append(DetectedTech(
                name=name_match.group(1).strip(),
                version=_clean_version(name_match.group(2)),
                source="page meta tag",
                evidence=f'meta generator: {content[:100]}',
            ))

    for pattern, tech_name in HTML_SIGNATURES:
        match = re.search(pattern, html_text, re.IGNORECASE)
        if not match:
            continue
        version = ""
        if "version" in (match.groupdict() or {}):
            version = _clean_version(match.group("version"))
        found.append(DetectedTech(
            name=tech_name, version=version, source="page content",
            evidence=f"page contains {match.group(0)[:80]}",
        ))

    return found


def _from_paths(base_url: str, session: requests.Session,
                hints: set[str]) -> list[DetectedTech]:
    """
    Check a small number of well-known paths.

    Only paths worth checking are requested: everything on the list that is
    either a universal give-away (``/.git/config``) or matches something we
    already suspect, capped at :data:`MAX_PROBE_PATHS` so this stays polite.
    """
    found: list[DetectedTech] = []
    checked = 0

    for path, tech_name, plain_meaning in PATH_SIGNATURES:
        if checked >= MAX_PROBE_PATHS:
            break
        # Skip CMS-specific paths unless we already have a reason to suspect it.
        if tech_name in ("WordPress", "Joomla", "Drupal") and tech_name not in hints:
            continue

        response = _fetch(base_url.rstrip("/") + path, session, allow_redirects=False)
        checked += 1
        if response is None or response.status_code not in (200, 401, 403):
            continue

        # A 401/403 still proves the thing exists - it is just protected.
        protected = response.status_code in (401, 403)
        found.append(DetectedTech(
            name=tech_name,
            source="known file path",
            concern="" if protected else plain_meaning.capitalize() + ".",
            evidence=f"{path} returned HTTP {response.status_code}",
        ))

    return found


def _merge(technologies: Iterable[DetectedTech]) -> list[DetectedTech]:
    """
    Collapse duplicates, keeping the best information about each technology.

    The same software is often spotted several ways; we prefer the sighting
    that came with a version number, since that is what makes it actionable.
    """
    best: dict[str, DetectedTech] = {}

    for tech in technologies:
        name = (tech.name or "").strip()
        if not name:
            continue

        key = name.lower()
        existing = best.get(key)
        if existing is None:
            best[key] = tech
            continue

        if tech.version and not existing.version:
            tech.concern = tech.concern or existing.concern
            best[key] = tech
        elif tech.concern and not existing.concern:
            existing.concern = tech.concern

    return list(best.values())


def detect_on_host(host: str, session: Optional[requests.Session] = None,
                   probe_paths: bool = True) -> HostTechReport:
    """
    Detect the technologies behind a single hostname.

    Tries HTTPS first and falls back to HTTP, which is what a browser
    effectively does. Never raises: an unreachable host is a normal outcome
    when scanning subdomains discovered by brute force.
    """
    report = HostTechReport(host=host)
    own_session = session is None
    session = session or requests.Session()

    try:
        response = None
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            response = _fetch(url, session)
            if response is not None:
                report.url = url
                break

        if response is None:
            report.error = "did not respond"
            log.debug("No response from %s", host)
            return report

        report.status_code = response.status_code

        html_text = ""
        content_type = str(response.headers.get("Content-Type", "")).lower()
        if "html" in content_type or not content_type:
            html_text = response.text[:400_000]   # cap: some pages are enormous

        found: list[DetectedTech] = []
        found += _from_headers(response)
        found += _from_cookies(response)
        found += _from_html(html_text)

        if probe_paths:
            hints = {t.name for t in found}
            found += _from_paths(report.url, session, hints)

        technologies = _merge(found)

        for tech in technologies:
            outdated, concern = check_outdated(tech.name, tech.version)
            if outdated:
                tech.outdated = True
                tech.concern  = concern or tech.concern

        report.technologies = sorted(technologies, key=lambda t: t.name.lower())
        log.info("%s: %s", host, ", ".join(
            f"{t.name}{' ' + t.version if t.version else ''}" for t in report.technologies
        ) or "nothing identified")

    except Exception as exc:
        report.error = str(exc)
        log.error("Technology detection failed for %s: %s", host, exc)
    finally:
        if own_session:
            session.close()

    return report


# ===========================================================================
# Graph integration
# ===========================================================================

def _hosts_to_check(graph: AttackSurfaceGraph, hosts: Optional[list[str]]) -> list[str]:
    """Which hostnames should we look at? Defaults to the domain plus subdomains."""
    if hosts:
        return list(hosts)

    found = graph.nodes_by_type(NodeType.DOMAIN) + graph.nodes_by_type(NodeType.SUBDOMAIN)
    return [h for h in found if graph.G.nodes[h].get("exposed", True)]


def detect_technologies(graph: AttackSurfaceGraph,
                        hosts: Optional[list[str]] = None,
                        max_hosts: int = 25,
                        probe_paths: bool = True) -> dict[str, HostTechReport]:
    """
    Detect technologies across the graph and add what is found as nodes.

    For every technology discovered, a ``technology`` node is created (or
    reused) and linked to the host it was seen on with a ``uses`` edge - the
    same shape ``port_scanner.py`` already produces, so the CVE lookup, the
    reporting engine and the attack path engine all pick it up with no changes.

    Args:
        graph       : the graph to enrich
        hosts       : specific hostnames, or None for every exposed host
        max_hosts   : safety cap, so a brute-forced list of 500 subdomains does
                      not turn into 500 web requests
        probe_paths : also check well-known paths such as /wp-login.php

    Returns a mapping of hostname -> :class:`HostTechReport`.
    """
    targets = _hosts_to_check(graph, hosts)[:max_hosts]
    if not targets:
        log.warning("No hosts to check for technologies.")
        return {}

    log.info("Detecting technologies on %d host(s) ...", len(targets))
    results: dict[str, HostTechReport] = {}
    session = requests.Session()

    try:
        for host in targets:
            report = detect_on_host(host, session=session, probe_paths=probe_paths)
            results[host] = report

            if not report.technologies:
                continue

            for tech in report.technologies:
                try:
                    _add_tech_to_graph(graph, host, tech)
                except Exception as exc:
                    log.error("Could not add %s on %s to the graph: %s",
                              tech.name, host, exc)
    finally:
        session.close()

    total = sum(len(r.technologies) for r in results.values())
    log.info("Technology detection complete: %d found across %d host(s).",
             total, len(results))
    return results


def _add_tech_to_graph(graph: AttackSurfaceGraph, host: str, tech: DetectedTech) -> str:
    """
    Add one detected technology as a node linked to its host.

    Uses ``add_technology()`` where possible so the node ID convention stays
    identical to the rest of the project (``tech:nginx``), then records the
    extra detail this scanner knows about.
    """
    if host not in graph.G:
        graph.add_node(NodeData(
            node_id=host, node_type=NodeType.SUBDOMAIN, label=host, exposed=True,
        ))

    tech_id = graph.add_technology(host, tech.name, tech.version)

    node = graph.G.nodes[tech_id]
    meta = node.get("meta") if isinstance(node.get("meta"), dict) else {}

    # Keep the first version we learn, but never overwrite a known version
    # with a blank one from a weaker signal.
    if tech.version and not meta.get("version"):
        meta["version"] = tech.version

    meta.setdefault("detected_by", tech.source)
    meta.setdefault("evidence", tech.evidence)
    meta.setdefault("seen_on", [])
    if host not in meta["seen_on"]:
        meta["seen_on"].append(host)

    if tech.outdated:
        meta["outdated"] = True
        meta["concern"]  = tech.concern
        # Outdated software carries real risk even before any CVE is matched.
        node["risk_score"] = max(float(node.get("risk_score") or 0.0), 6.5)
    elif tech.concern:
        meta["concern"] = tech.concern
        node["risk_score"] = max(float(node.get("risk_score") or 0.0), 5.0)

    node["meta"] = meta
    node["exposed"] = True
    return tech_id


def outdated_technologies(graph: AttackSurfaceGraph) -> list[dict]:
    """
    Every technology node flagged as out of date, for the reports.

    Returned in plain English so the PDF and the web dashboard can show it
    without any further translation.
    """
    outdated: list[dict] = []

    for node_id in graph.nodes_by_type(NodeType.TECHNOLOGY):
        attrs = graph.G.nodes[node_id]
        meta  = attrs.get("meta") if isinstance(attrs.get("meta"), dict) else {}
        if not meta.get("outdated"):
            continue

        outdated.append({
            "node_id": node_id,
            "name":    attrs.get("label", node_id),
            "version": meta.get("version", ""),
            "concern": meta.get("concern", ""),
            "hosts":   meta.get("seen_on", []),
        })

    return outdated


# ===========================================================================
# CLI:  python -m scanners.tech_detect example.com
# ===========================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(
        description="Detect the technologies behind a website."
    )
    parser.add_argument("host", nargs="+", help="Hostname(s) to inspect")
    parser.add_argument("--no-paths", action="store_true",
                        help="Do not check well-known paths such as /wp-login.php")
    args = parser.parse_args()

    for hostname in args.host:
        result = detect_on_host(hostname, probe_paths=not args.no_paths)
        print(f"\n{hostname}  ({result.url or 'no response'})")
        print("-" * 60)

        if result.error:
            print(f"  Could not check this host: {result.error}")
            continue
        if not result.technologies:
            print("  Nothing identified.")
            continue

        for item in result.technologies:
            version = f" {item.version}" if item.version else ""
            flag    = "  [OUT OF DATE]" if item.outdated else ""
            print(f"  {item.name}{version}{flag}")
            print(f"      seen in: {item.source} ({item.evidence})")
            if item.concern:
                print(f"      concern: {item.concern}")
