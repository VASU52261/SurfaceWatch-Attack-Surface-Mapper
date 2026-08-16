"""
demo.py
-------
Simulates scanner output and feeds it into the graph builder.
Run with:  python demo.py
"""

from graph.builder import AttackSurfaceGraph

def main():
    g = AttackSurfaceGraph(target="example.com")

    # ── 1. Domain & IPs ────────────────────────────────────────────────
    g.add_domain("example.com")
    g.add_subdomain("api.example.com",   "example.com")
    g.add_subdomain("admin.example.com", "example.com")

    g.add_ip("93.184.216.34")
    g.add_ip("10.0.0.5", exposed=False)   # internal IP

    g.link_domain_to_ip("example.com",       "93.184.216.34")
    g.link_domain_to_ip("api.example.com",   "93.184.216.34")
    g.link_domain_to_ip("admin.example.com", "10.0.0.5")

    # ── 2. Ports & services (Nmap output) ─────────────────────────────
    port_80  = g.add_port("93.184.216.34", 80)
    port_443 = g.add_port("93.184.216.34", 443)
    port_22  = g.add_port("93.184.216.34", 22)
    port_db  = g.add_port("10.0.0.5", 5432)

    svc_nginx  = g.add_service(port_80,  "nginx",      "1.18.0")
    svc_tls    = g.add_service(port_443, "nginx-ssl",  "1.18.0")
    svc_ssh    = g.add_service(port_22,  "OpenSSH",    "8.2p1")
    svc_pg     = g.add_service(port_db,  "PostgreSQL", "13.3")

    # ── 3. Technologies ───────────────────────────────────────────────
    g.add_technology(svc_nginx, "Nginx",   "1.18.0")
    g.add_technology(svc_nginx, "Ubuntu")
    g.add_technology(svc_tls,   "OpenSSL", "1.1.1f")

    # ── 4. CVEs (from CVE lookup module) ─────────────────────────────
    g.add_cve(svc_nginx,           "CVE-2021-23017", cvss=7.7,
              description="Off-by-one in nginx resolver")
    g.add_cve("tech:OpenSSL",      "CVE-2022-0778",  cvss=7.5,
              description="Infinite loop in BN_mod_sqrt")
    g.add_cve(svc_ssh,             "CVE-2023-38408", cvss=9.8,
              description="Remote code exec via ssh-agent")

    # ── 5. Summary ────────────────────────────────────────────────────
    print("\n=== Graph Summary ===")
    for k, v in g.summary().items():
        print(f"  {k}: {v}")

    # ── 6. Top risk nodes ─────────────────────────────────────────────
    print("\n=== Top 5 Risk Nodes ===")
    for rank, node in enumerate(g.top_risk_nodes(top_n=5), 1):
        print(f"  {rank}. [{node['node_type']:12}] {node['label']:<30}"
              f"combined={node['combined']:.3f}  exposed={node['exposed']}")

    # ── 7. Attack path ────────────────────────────────────────────────
    path = g.shortest_attack_path("example.com", "CVE-2023-38408")
    print("\n=== Shortest attack path: example.com → CVE-2023-38408 ===")
    if path:
        print("  " + " → ".join(path))
    else:
        print("  No path found.")

    # ── 8. Save ───────────────────────────────────────────────────────
    g.save("attack_surface.json")
    print("\nGraph saved to attack_surface.json")


if __name__ == "__main__":
    main()
