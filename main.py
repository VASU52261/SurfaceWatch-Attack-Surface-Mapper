"""
main.py
-------
Main entry point for the Attack Surface Mapper.
"""

import argparse
import logging

from graph.builder import AttackSurfaceGraph
from scanners.port_scanner import scan_ports
from scanners.subdomain_enum import enumerate_subdomains
from scanners.cve_lookup import lookup_cves_for_graph

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(description="Attack Surface Mapper")
    parser.add_argument("--target",   required=True, help="Domain or IP to scan")
    parser.add_argument("--ports",    default="21,22,23,25,53,80,443,445,3306,3389,5432,8080,8443",
                        help="Port range or list to scan")
    parser.add_argument("--skip-cve", action="store_true",
                        help="Skip CVE lookup (faster, offline)")
    parser.add_argument("--output",   default="attack_surface.json",
                        help="Output file path")
    args = parser.parse_args()

    print(f"\n{'='*50}")
    print(f"  Attack Surface Mapper")
    print(f"  Target : {args.target}")
    print(f"  Ports  : {args.ports}")
    print(f"{'='*50}\n")

    graph = AttackSurfaceGraph(target=args.target)
    graph.add_domain(args.target)

    print("[1/3] Enumerating subdomains ...")
    subdomains = enumerate_subdomains(graph, args.target)
    print(f"      Found {len(subdomains)} subdomains\n")

    print("[2/3] Scanning ports ...")
    scan_ports(graph, args.target, ports=args.ports)

    for sub in subdomains[:3]:
        scan_ports(graph, sub, ports=args.ports)

    if not args.skip_cve:
        print("\n[3/3] Looking up CVEs ...")
        lookup_cves_for_graph(graph)
    else:
        print("\n[3/3] CVE lookup skipped.")

    print(f"\n{'='*50}")
    summary = graph.summary()
    for k, v in summary.items():
        print(f"  {k}: {v}")

    print("\n  Top 10 Riskiest Nodes:")
    for rank, node in enumerate(graph.top_risk_nodes(top_n=10), 1):
        print(f"  {rank:2}. [{node['node_type']:12}] {node['label']:<28} "
              f"combined={node['combined']:.3f}  exposed={node['exposed']}")

    graph.save(args.output)
    print(f"\n  Graph saved to {args.output}")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()