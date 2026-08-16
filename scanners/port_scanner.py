"""
scanners/port_scanner.py
------------------------
Scans open ports and services on a target IP using Nmap.
Feeds results directly into the AttackSurfaceGraph.
"""

import logging
import socket
import nmap

from graph.builder import AttackSurfaceGraph

log = logging.getLogger(__name__)


def resolve_domain(domain: str) -> str | None:
    """Resolve a domain name to its IP address."""
    try:
        ip = socket.gethostbyname(domain)
        log.info("Resolved %s → %s", domain, ip)
        return ip
    except socket.gaierror:
        log.error("Could not resolve domain: %s", domain)
        return None


import os as _os

# Common Nmap install locations on Windows - checked if nmap isn't in PATH
_NMAP_SEARCH_PATHS = [
    r"C:\Program Files (x86)\Nmap",
    r"C:\Program Files\Nmap",
]


def _ensure_nmap_in_path():
    """
    If nmap.exe isn't reachable via the current PATH, find it in common
    Windows install locations and add that folder directly to this
    process's PATH environment variable (os.environ), which python-nmap
    actually respects (unlike its nmap_search_path parameter).
    """
    for path in _NMAP_SEARCH_PATHS:
        exe = _os.path.join(path, "nmap.exe")
        if _os.path.exists(exe):
            current_path = _os.environ.get("PATH", "")
            if path.lower() not in current_path.lower():
                _os.environ["PATH"] = current_path + _os.pathsep + path
                log.info("Added Nmap folder to PATH: %s", path)
            return True
    return False


def _get_nmap_scanner() -> nmap.PortScanner:
    """Create an Nmap PortScanner, fixing PATH first if needed."""
    try:
        return nmap.PortScanner()
    except nmap.PortScannerError:
        if _ensure_nmap_in_path():
            return nmap.PortScanner()  # retry now that PATH is fixed
        raise  # nmap truly isn't installed anywhere we checked


def scan_ports(graph: AttackSurfaceGraph, target: str, ports: str = "1-1024") -> None:
    """
    Run an Nmap scan on the target and add results to the graph.

    Args:
        graph   : the AttackSurfaceGraph instance to populate
        target  : domain name or IP address
        ports   : port range string e.g. "1-1024" or "22,80,443,8080"
    """
    nm = _get_nmap_scanner()

    # Resolve domain → IP if needed
    ip = target if _is_ip(target) else resolve_domain(target)
    if not ip:
        log.error("Skipping port scan — could not resolve %s", target)
        return

    log.info("Starting port scan on %s (ports: %s) ...", ip, ports)

    # -sV  = version detection
    # -T4  = aggressive timing (faster)
    # --open = only show open ports
    try:
        nm.scan(hosts=ip, ports=ports, arguments="-sV -T4 --open")
    except nmap.PortScannerError as e:
        log.error("Nmap error: %s", e)
        log.error("Make sure Nmap is installed and you're running as Administrator.")
        return

    if ip not in nm.all_hosts():
        log.warning("No results for %s — host may be down or blocking scans.", ip)
        return

    # Add IP node to graph
    graph.add_ip(ip, exposed=True)

    # Link domain → IP if target was a domain
    if not _is_ip(target) and target in graph.G:
        graph.link_domain_to_ip(target, ip)

    host_info = nm[ip]
    log.info("Host state: %s", host_info.state())

    # Walk through TCP ports
    for proto in host_info.all_protocols():
        ports_dict = host_info[proto]
        for port, port_info in ports_dict.items():
            state   = port_info.get("state", "")
            service = port_info.get("name", "unknown")
            version = port_info.get("version", "")
            product = port_info.get("product", "")

            if state != "open":
                continue

            # Add port node + edge ip → exposes → port
            port_id = graph.add_port(ip, port, proto)

            # Add service node + edge service → runs_on → port
            svc_name = product if product else service
            svc_id   = graph.add_service(port_id, svc_name, version)

            log.info("  [OPEN] %s/%s  %s %s", port, proto, svc_name, version)

            # Add technology node if product detected
            if product:
                graph.add_technology(svc_id, product, version)

    log.info("Port scan complete for %s", ip)


def _is_ip(value: str) -> bool:
    """Check if a string looks like an IP address."""
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)