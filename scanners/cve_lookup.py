"""
scanners/cve_lookup.py
----------------------
Looks up CVEs from the NIST NVD API v2.
- Uses API key if available (10x faster, 50 req/30s vs 5 req/30s)
- Retries automatically on failure
- Always prefers CVSSv3 scores
- Filters out low-severity CVEs (CVSS < 4.0)
- Stores API key safely in .env file
"""

import logging
import time
import os
import requests
from dotenv import load_dotenv

from graph.builder import AttackSurfaceGraph, NodeType

# Load .env file (NVD_API_KEY lives here)
load_dotenv()

log = logging.getLogger(__name__)

NVD_API_URL       = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_CVES_PER_NODE = 5     # how many CVEs to add per service/technology
MIN_CVSS_SCORE    = 4.0   # ignore low-severity CVEs below this
MAX_RETRIES       = 3     # retry failed requests this many times


def _get_headers() -> dict:
    api_key = os.getenv("NVD_API_KEY", "")
    if api_key:
        return {"apiKey": api_key}
    return {}


def _request_delay() -> float:
    return 0.6 if os.getenv("NVD_API_KEY") else 7.0


def _fetch_cves(keyword: str, max_results: int = 5) -> list[dict]:
    params = {
        "keywordSearch":     keyword,
        "resultsPerPage":    max_results * 2,
        "keywordExactMatch": False,
    }

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.get(NVD_API_URL, params=params,
                                headers=_get_headers(), timeout=20)
            if resp.status_code == 403:
                log.warning("NVD rate limit hit — waiting 30s...")
                time.sleep(30)
                continue
            resp.raise_for_status()
            data = resp.json()
            break
        except requests.RequestException as e:
            log.error("NVD request failed (attempt %d/%d): %s", attempt, MAX_RETRIES, e)
            if attempt < MAX_RETRIES:
                time.sleep(5 * attempt)
            else:
                return []
    else:
        return []

    cves = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id   = cve_data.get("id", "")
        if not cve_id:
            continue

        cvss = 0.0
        severity = ""
        cvss_vector = ""
        metrics = cve_data.get("metrics", {})

        for key in ("cvssMetricV31", "cvssMetricV30"):
            if key in metrics and metrics[key]:
                cvss_data   = metrics[key][0].get("cvssData", {})
                cvss        = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                severity    = cvss_data.get("baseSeverity", "")
                break

        if cvss == 0.0 and "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
            cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            cvss      = cvss_data.get("baseScore", 0.0)
            severity  = metrics["cvssMetricV2"][0].get("baseSeverity", "")

        if cvss < MIN_CVSS_SCORE:
            continue

        descriptions = cve_data.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "No description available."
        )
        published = cve_data.get("published", "")[:10]

        cves.append({
            "cve_id":      cve_id,
            "cvss":        cvss,
            "severity":    severity,
            "vector":      cvss_vector,
            "description": desc[:250],
            "published":   published,
        })

    return sorted(cves, key=lambda x: x["cvss"], reverse=True)[:max_results]


def lookup_cves_for_graph(graph: AttackSurfaceGraph) -> int:
    targets = (
        graph.nodes_by_type(NodeType.SERVICE) +
        graph.nodes_by_type(NodeType.TECHNOLOGY)
    )

    if not targets:
        log.warning("No service or technology nodes found in graph.")
        return 0

    has_key = bool(os.getenv("NVD_API_KEY"))
    delay   = _request_delay()
    total   = 0

    log.info("CVE lookup for %d nodes (API key: %s)",
             len(targets), "YES ✓" if has_key else "NO — public rate limit")

    if not has_key:
        est = len(targets) * delay
        log.info("Estimated time: ~%d seconds (~%d min)", int(est), int(est/60))

    for i, node_id in enumerate(targets, 1):
        attrs   = graph.G.nodes[node_id]
        label   = attrs.get("label", node_id)
        version = attrs.get("meta", {}).get("version", "")
        keyword = f"{label} {version}".strip()

        log.info("[%d/%d] Querying: '%s'", i, len(targets), keyword)
        cves = _fetch_cves(keyword, max_results=MAX_CVES_PER_NODE)

        for cve in cves:
            graph.add_cve(node_id, cve["cve_id"], cve["cvss"], cve["description"])
            graph.G.nodes[cve["cve_id"]]["meta"] = {
                "cvss":        cve["cvss"],
                "severity":    cve["severity"],
                "vector":      cve["vector"],
                "published":   cve["published"],
                # This assignment replaces the meta dict that add_cve() set, so
                # the description has to be carried across. Without it the
                # plain English reports lose the one piece of text they use to
                # work out what a weakness actually lets an attacker do.
                "description": cve["description"],
            }
            log.info("  [CVE] %s  CVSS=%.1f  %s",
                     cve["cve_id"], cve["cvss"], cve["severity"])
            total += 1

        if not cves:
            log.info("  No significant CVEs for '%s'", keyword)

        time.sleep(delay)

    log.info("CVE lookup complete. Total added: %d", total)
    return total
