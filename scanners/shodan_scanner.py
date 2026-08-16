"""
scanners/shodan_scanner.py
--------------------------
Asks Shodan what it already knows about your servers.

Shodan continuously scans the whole internet and publishes what it finds. That
makes it useful here for two reasons:

    1. It is completely passive. We ask Shodan's database a question; we never
       touch the business's servers. That means it works even when a firewall
       blocks our own port scan, and it is safe to run against a host you have
       not been given permission to scan actively.
    2. It sees the internet from the outside, continuously. Shodan may already
       know about a port that was open last week and closed the morning we
       looked.

For every IP in the graph it collects open ports and services, known
vulnerabilities, device type, organisation, country and ISP, then adds them to
the graph as ordinary nodes so the rest of SurfaceWatch treats them like any other
finding.

The API key is read from ``.env`` as ``SHODAN_API_KEY`` and is never written to
a log or a scan file. Without a key this module logs one line and skips - it is
an enhancement, not a requirement.

Get a free key at https://account.shodan.io/. The free tier is enough for a
small business monitoring a handful of addresses.

Usage::

    from scanners.shodan_scanner import enrich_graph_with_shodan
    enrich_graph_with_shodan(graph)
"""

from __future__ import annotations

import ipaddress
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Optional

import requests
from dotenv import load_dotenv

from graph.builder import AttackSurfaceGraph, NodeType

load_dotenv()

log = logging.getLogger(__name__)

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
SHODAN_INFO_URL = "https://api.shodan.io/api-info"

REQUEST_TIMEOUT = 20
REQUEST_DELAY   = 1.1     # free tier allows roughly one request per second
MAX_RETRIES     = 3


# ===========================================================================
# Results
# ===========================================================================

@dataclass
class ShodanHost:
    """What Shodan knows about one IP address."""

    ip: str
    ports: list[int] = field(default_factory=list)
    services: list[dict] = field(default_factory=list)   # port, product, version
    vulns: list[str] = field(default_factory=list)
    organization: str = ""
    isp: str = ""
    country: str = ""
    city: str = ""
    device_type: str = ""
    operating_system: str = ""
    hostnames: list[str] = field(default_factory=list)
    last_update: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return not self.error

    def to_dict(self) -> dict:
        return {
            "ip":               self.ip,
            "ports":            self.ports,
            "services":         self.services,
            "vulns":            self.vulns,
            "organization":     self.organization,
            "isp":              self.isp,
            "country":          self.country,
            "city":             self.city,
            "device_type":      self.device_type,
            "operating_system": self.operating_system,
            "hostnames":        self.hostnames,
            "last_update":      self.last_update,
            "error":            self.error,
        }

    def plain_summary(self) -> str:
        """One sentence a business owner can read about where this server is."""
        bits = []
        if self.organization:
            bits.append(f"hosted by {self.organization}")
        elif self.isp:
            bits.append(f"on {self.isp}")
        if self.country:
            bits.append(f"in {self.country}")

        where = ", ".join(bits) if bits else "at an unknown provider"
        count = len(self.ports)
        doors = (f"{count} open door{'s' if count != 1 else ''}"
                 if count else "no open doors")
        return f"This server is {where}, with {doors} visible from the internet."


# ===========================================================================
# API access
# ===========================================================================

def get_api_key() -> str:
    """Read ``SHODAN_API_KEY`` from the environment. Never hard-code it."""
    return os.getenv("SHODAN_API_KEY", "").strip()


def is_configured() -> bool:
    """True when a Shodan key is available."""
    return bool(get_api_key())


def check_api_key(api_key: Optional[str] = None) -> Optional[dict]:
    """
    Confirm the key works and report the remaining quota.

    Returns Shodan's plan info, or ``None`` if the key is missing or rejected.
    Handy for the CLI so a user can tell a wrong key from a quiet one.
    """
    api_key = api_key or get_api_key()
    if not api_key:
        return None

    try:
        response = requests.get(SHODAN_INFO_URL, params={"key": api_key},
                                timeout=REQUEST_TIMEOUT)
        if response.status_code == 401:
            log.error("Shodan rejected the API key. Check SHODAN_API_KEY in your .env file.")
            return None
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        log.error("Could not reach Shodan: %s", exc)
        return None


def _is_public_ip(value: str) -> bool:
    """
    Only public addresses are worth asking Shodan about.

    Private ranges (10.x, 192.168.x) are internal to the business, so Shodan
    has nothing on them and querying wastes quota.
    """
    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError:
        return False
    return not (address.is_private or address.is_loopback
                or address.is_reserved or address.is_link_local)


def lookup_ip(ip: str, api_key: Optional[str] = None) -> ShodanHost:
    """
    Ask Shodan about one IP address.

    Never raises. A 404 simply means Shodan has no record of this address,
    which is a perfectly normal - and mildly good - result.
    """
    host = ShodanHost(ip=ip)

    api_key = api_key or get_api_key()
    if not api_key:
        host.error = "no API key"
        return host

    if not _is_public_ip(ip):
        host.error = "internal address, not on Shodan"
        log.debug("Skipping private address %s", ip)
        return host

    data: Optional[dict] = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            response = requests.get(
                SHODAN_HOST_URL.format(ip=ip),
                params={"key": api_key, "minify": "false"},
                timeout=REQUEST_TIMEOUT,
            )

            if response.status_code == 404:
                host.error = "no record on Shodan"
                log.info("Shodan has no record of %s", ip)
                return host
            if response.status_code == 401:
                host.error = "the API key was rejected"
                log.error("Shodan rejected the API key.")
                return host
            if response.status_code == 429:
                log.warning("Shodan rate limit reached - waiting before retrying.")
                time.sleep(5 * attempt)
                continue

            response.raise_for_status()
            data = response.json()
            break

        except requests.RequestException as exc:
            log.error("Shodan request for %s failed (attempt %d/%d): %s",
                      ip, attempt, MAX_RETRIES, exc)
            if attempt < MAX_RETRIES:
                time.sleep(2 * attempt)
            else:
                host.error = str(exc)[:160]
                return host

    if not data:
        host.error = host.error or "no data returned"
        return host

    # ---- the parts we care about ----------------------------------------
    host.ports        = sorted({int(p) for p in data.get("ports", []) if str(p).isdigit()})
    host.organization = str(data.get("org") or "")
    host.isp          = str(data.get("isp") or "")
    host.country      = str(data.get("country_name") or "")
    host.city         = str(data.get("city") or "")
    host.operating_system = str(data.get("os") or "")
    host.last_update  = str(data.get("last_update") or "")[:10]
    host.hostnames    = [str(h) for h in (data.get("hostnames") or [])]
    host.vulns        = sorted(str(v) for v in (data.get("vulns") or []))

    for item in data.get("data", []) or []:
        if not isinstance(item, dict):
            continue
        service = {
            "port":      item.get("port"),
            "transport": item.get("transport", "tcp"),
            "product":   str(item.get("product") or ""),
            "version":   str(item.get("version") or ""),
            "vulns":     sorted((item.get("vulns") or {}).keys())
                         if isinstance(item.get("vulns"), dict) else [],
        }
        host.services.append(service)

        if not host.device_type:
            host.device_type = str(item.get("devicetype") or "")

    log.info("Shodan: %s has %d open port(s), %d known weakness(es) - %s",
             ip, len(host.ports), len(host.vulns),
             host.organization or host.isp or "unknown provider")
    return host


# ===========================================================================
# Graph integration
# ===========================================================================

def enrich_graph_with_shodan(graph: AttackSurfaceGraph,
                             ips: Optional[list[str]] = None,
                             api_key: Optional[str] = None,
                             max_ips: int = 25) -> dict[str, ShodanHost]:
    """
    Look every IP in the graph up on Shodan and merge what comes back.

    Ports and services Shodan reports are added using the graph's own builder
    methods, so they are indistinguishable from Nmap findings to the rest of
    the system - the report engine, attack story engine and diff engine all
    handle them with no changes. Each node is marked with ``source: "shodan"``
    so it is still possible to tell where a fact came from.

    Skips silently and returns ``{}`` when no API key is set.
    """
    api_key = api_key or get_api_key()
    if not api_key:
        log.info(
            "Shodan lookup skipped - no API key set. Add SHODAN_API_KEY to your "
            ".env file to enable it (free keys at https://account.shodan.io/)."
        )
        return {}

    targets = ips if ips is not None else graph.nodes_by_type(NodeType.IP)
    targets = [ip for ip in targets if _is_public_ip(ip)][:max_ips]

    if not targets:
        log.info("No public IP addresses in the graph to look up on Shodan.")
        return {}

    log.info("Asking Shodan about %d address(es) ...", len(targets))
    results: dict[str, ShodanHost] = {}

    for index, ip in enumerate(targets, 1):
        host = lookup_ip(ip, api_key=api_key)
        results[ip] = host

        if host.ok:
            try:
                _merge_into_graph(graph, host)
            except Exception as exc:
                log.error("Could not merge Shodan data for %s: %s", ip, exc)

        if index < len(targets):
            time.sleep(REQUEST_DELAY)     # stay inside the free tier's limit

    found = sum(1 for h in results.values() if h.ok)
    log.info("Shodan lookup complete: %d of %d address(es) had records.",
             found, len(results))
    return results


def _merge_into_graph(graph: AttackSurfaceGraph, host: ShodanHost) -> None:
    """Add everything Shodan reported about one IP into the graph."""
    ip = host.ip

    if ip not in graph.G:
        graph.add_ip(ip, exposed=True)

    # ---- what we learned about the server itself ------------------------
    node = graph.G.nodes[ip]
    meta = node.get("meta") if isinstance(node.get("meta"), dict) else {}
    meta.update({
        "organization":     host.organization,
        "isp":              host.isp,
        "country":          host.country,
        "city":             host.city,
        "device_type":      host.device_type,
        "operating_system": host.operating_system,
        "shodan_last_seen": host.last_update,
        "plain_summary":    host.plain_summary(),
        "source":           "shodan",
    })
    node["meta"] = meta

    # ---- ports and services ---------------------------------------------
    services_by_port = {
        int(s["port"]): s for s in host.services
        if str(s.get("port", "")).isdigit()
    }

    for port in host.ports:
        service  = services_by_port.get(port, {})
        protocol = str(service.get("transport") or "tcp")

        port_id = f"{ip}:{port}/{protocol}"
        newly_seen = port_id not in graph.G

        if newly_seen:
            port_id = graph.add_port(ip, port, protocol)

        port_meta = graph.G.nodes[port_id].get("meta") or {}
        port_meta.setdefault("source", "shodan" if newly_seen else "nmap+shodan")
        graph.G.nodes[port_id]["meta"] = port_meta

        product = str(service.get("product") or "").strip()
        if not product:
            continue

        version = str(service.get("version") or "").strip()
        svc_id  = f"svc:{product}@{port_id}"
        if svc_id not in graph.G:
            svc_id = graph.add_service(port_id, product, version)
            graph.G.nodes[svc_id]["meta"] = {
                "version": version, "source": "shodan",
            }
            graph.add_technology(svc_id, product, version)

        # Weaknesses Shodan has already matched to this exact service.
        for cve_id in service.get("vulns", []) or []:
            _add_shodan_cve(graph, svc_id, cve_id)

    # ---- host-wide vulnerabilities --------------------------------------
    # These are not tied to a specific service, so they attach to the IP.
    for cve_id in host.vulns:
        _add_shodan_cve(graph, ip, cve_id)


def _add_shodan_cve(graph: AttackSurfaceGraph, asset_id: str, cve_id: str) -> None:
    """
    Record a weakness Shodan reported.

    Shodan does not always include a CVSS score in the host response. Rather
    than invent one, we add the weakness with a score of 0.0 and mark it
    ``needs_score``; ``scanners/cve_lookup.py`` fills in the real severity from
    the NVD, and the reporting engine already treats a missing score as LOW so
    nothing is ever silently over-stated.
    """
    cve_id = str(cve_id).strip().upper()
    if not cve_id.startswith("CVE-"):
        return

    existing = graph.G.nodes.get(cve_id)
    cvss = 0.0
    if existing:
        meta = existing.get("meta") if isinstance(existing.get("meta"), dict) else {}
        cvss = float(meta.get("cvss") or existing.get("risk_score") or 0.0)

    graph.add_cve(asset_id, cve_id, cvss, description="")

    node = graph.G.nodes[cve_id]
    meta = node.get("meta") if isinstance(node.get("meta"), dict) else {}
    meta.setdefault("source", "shodan")
    if not meta.get("cvss"):
        meta["needs_score"] = True
    node["meta"] = meta


def shodan_summary(results: dict[str, ShodanHost]) -> dict[str, Any]:
    """A small plain English summary of a Shodan run, for the reports."""
    found = {ip: host for ip, host in results.items() if host.ok}

    countries    = sorted({h.country for h in found.values() if h.country})
    providers    = sorted({h.organization or h.isp for h in found.values()
                           if h.organization or h.isp})
    total_vulns  = sum(len(h.vulns) for h in found.values())
    total_ports  = sum(len(h.ports) for h in found.values())

    return {
        "addresses_checked":  len(results),
        "addresses_found":    len(found),
        "open_ports_seen":    total_ports,
        "known_weaknesses":   total_vulns,
        "countries":          countries,
        "providers":          providers,
        "plain":              (
            f"Shodan, a public search engine for internet-connected devices, "
            f"already lists {len(found)} of your {len(results)} servers. "
            f"Anyone can look this up without touching your systems."
            if found else
            "Shodan has no public record of your servers, which is a good sign."
        ),
    }


# ===========================================================================
# CLI:  python -m scanners.shodan_scanner 8.8.8.8
# ===========================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(
        description="Ask Shodan what it knows about an IP address."
    )
    parser.add_argument("ip", nargs="*", help="IP address(es) to look up")
    parser.add_argument("--check-key", action="store_true",
                        help="Check the API key and show the remaining quota")
    args = parser.parse_args()

    if args.check_key:
        info = check_api_key()
        if info is None:
            raise SystemExit(
                "No working Shodan key. Set SHODAN_API_KEY in your .env file."
            )
        print(f"Shodan key works. Plan: {info.get('plan', 'unknown')}, "
              f"query credits left: {info.get('query_credits', '?')}")
        raise SystemExit(0)

    if not args.ip:
        raise SystemExit("Give at least one IP address, or use --check-key.")

    if not is_configured():
        raise SystemExit(
            "No Shodan API key found. Add SHODAN_API_KEY to your .env file "
            "(free keys at https://account.shodan.io/)."
        )

    for address in args.ip:
        result = lookup_ip(address)
        print(f"\n{address}")
        print("-" * 60)
        if not result.ok:
            print(f"  {result.error}")
            continue

        print(f"  {result.plain_summary()}")
        if result.ports:
            print(f"  Open ports : {', '.join(str(p) for p in result.ports)}")
        if result.operating_system:
            print(f"  Runs       : {result.operating_system}")
        if result.device_type:
            print(f"  Device type: {result.device_type}")
        if result.vulns:
            print(f"  Weaknesses : {len(result.vulns)} listed publicly")
        if result.last_update:
            print(f"  Last seen  : {result.last_update}")
