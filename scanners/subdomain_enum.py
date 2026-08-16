"""
scanners/subdomain_enum.py
--------------------------
Enumerates subdomains using a wordlist-based DNS brute force.
No external API needed — works purely via DNS resolution.
Feeds results into the AttackSurfaceGraph.
"""

import logging
import socket
import concurrent.futures
from typing import Optional

from graph.builder import AttackSurfaceGraph

log = logging.getLogger(__name__)

# Common subdomain wordlist — extend this as needed
DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap",
    "api", "dev", "staging", "test", "uat", "prod", "app",
    "admin", "portal", "dashboard", "login", "auth", "sso",
    "cdn", "static", "assets", "media", "images", "files",
    "blog", "shop", "store", "support", "help", "docs",
    "vpn", "remote", "ssh", "git", "gitlab", "github",
    "jenkins", "ci", "build", "deploy", "monitor",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "ns1", "ns2", "mx", "mx1", "mx2",
    "mobile", "m", "beta", "alpha", "demo",
]


def _try_resolve(subdomain: str, domain: str) -> Optional[tuple[str, str]]:
    """
    Try to resolve subdomain.domain → IP.
    Returns (full_subdomain, ip) or None if it doesn't resolve.
    """
    full = f"{subdomain}.{domain}"
    try:
        ip = socket.gethostbyname(full)
        return (full, ip)
    except socket.gaierror:
        return None


def enumerate_subdomains(
    graph: AttackSurfaceGraph,
    domain: str,
    wordlist: list[str] = None,
    max_workers: int = 20,
) -> list[str]:
    """
    Brute-force subdomain enumeration via DNS resolution.

    Args:
        graph       : AttackSurfaceGraph to populate
        domain      : root domain e.g. "example.com"
        wordlist    : list of subdomain prefixes to try
        max_workers : number of parallel DNS threads

    Returns:
        list of discovered subdomains
    """
    wordlist = wordlist or DEFAULT_WORDLIST
    discovered = []

    log.info("Starting subdomain enumeration for %s (%d words) ...", domain, len(wordlist))

    # Make sure the root domain exists in the graph
    if domain not in graph.G:
        graph.add_domain(domain)

    # Run DNS lookups in parallel for speed
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(_try_resolve, word, domain): word
            for word in wordlist
        }

        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result is None:
                continue

            full_sub, ip = result
            log.info("  [FOUND] %s → %s", full_sub, ip)

            # Add subdomain node + link to parent domain
            graph.add_subdomain(full_sub, domain)

            # Add IP and link
            graph.add_ip(ip, exposed=True)
            graph.link_domain_to_ip(full_sub, ip)

            discovered.append(full_sub)

    log.info("Subdomain enumeration complete. Found %d subdomains.", len(discovered))
    return discovered
