"""
graph/builder.py
----------------
Constructs and manages the attack surface graph using NetworkX.

Node types  : domain, subdomain, ip, port, service, technology, cve
Edge types  : resolves_to, runs_on, exposes, uses, is_vulnerable_to
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional

import networkx as nx

logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums — keeps node/edge types consistent across the whole project
# ---------------------------------------------------------------------------

class NodeType(str, Enum):
    DOMAIN      = "domain"
    SUBDOMAIN   = "subdomain"
    IP          = "ip"
    PORT        = "port"
    SERVICE     = "service"
    TECHNOLOGY  = "technology"
    CVE         = "cve"


class EdgeType(str, Enum):
    RESOLVES_TO      = "resolves_to"       # domain  → ip
    RUNS_ON          = "runs_on"           # service → ip
    EXPOSES          = "exposes"           # ip      → port
    USES             = "uses"              # service → technology
    IS_VULNERABLE_TO = "is_vulnerable_to"  # service/tech → cve


# ---------------------------------------------------------------------------
# Data classes — typed schemas for nodes and edges
# ---------------------------------------------------------------------------

@dataclass
class NodeData:
    node_id:    str
    node_type:  NodeType
    label:      str
    exposed:    bool        = False   # reachable from the public internet?
    risk_score: float       = 0.0    # 0.0–10.0 (filled in by risk_scorer.py)
    meta:       dict        = field(default_factory=dict)


@dataclass
class EdgeData:
    source:    str
    target:    str
    edge_type: EdgeType
    meta:      dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# AttackSurfaceGraph
# ---------------------------------------------------------------------------

class AttackSurfaceGraph:
    """
    Wraps a NetworkX DiGraph and provides domain-specific methods for
    adding assets, querying the graph, and running basic analyses.
    """

    def __init__(self, target: str):
        self.target = target
        self.G: nx.DiGraph = nx.DiGraph(target=target)
        # Cached attack_view(), keyed on (node count, edge count) so it is
        # rebuilt automatically whenever the graph grows.
        self._attack_view_cache: Optional[tuple[tuple[int, int], nx.DiGraph]] = None
        log.info("Graph initialised for target: %s", target)

    # ------------------------------------------------------------------
    # Builders
    # ------------------------------------------------------------------

    def add_node(self, data: NodeData) -> str:
        """Add or update a node. Returns the node_id."""
        attrs = asdict(data)
        attrs["node_type"] = data.node_type.value   # store as plain string
        self.G.add_node(data.node_id, **attrs)
        log.debug("Node added: %s (%s)", data.node_id, data.node_type.value)
        return data.node_id

    def add_edge(self, data: EdgeData) -> None:
        """Add a directed edge. Both nodes must already exist."""
        if data.source not in self.G:
            raise ValueError(f"Source node '{data.source}' not in graph.")
        if data.target not in self.G:
            raise ValueError(f"Target node '{data.target}' not in graph.")

        self.G.add_edge(
            data.source,
            data.target,
            edge_type=data.edge_type.value,
            **data.meta,
        )
        log.debug("Edge: %s --[%s]--> %s", data.source, data.edge_type.value, data.target)

    # ------------------------------------------------------------------
    # Convenience builders (used by scanner modules)
    # ------------------------------------------------------------------

    def add_domain(self, domain: str, exposed: bool = True) -> str:
        return self.add_node(NodeData(
            node_id=domain, node_type=NodeType.DOMAIN,
            label=domain, exposed=exposed,
        ))

    def add_subdomain(self, subdomain: str, parent_domain: str) -> str:
        nid = self.add_node(NodeData(
            node_id=subdomain, node_type=NodeType.SUBDOMAIN,
            label=subdomain, exposed=True,
        ))
        # auto-link subdomain → parent domain
        self.add_edge(EdgeData(
            source=subdomain, target=parent_domain,
            edge_type=EdgeType.RESOLVES_TO,
        ))
        return nid

    def add_ip(self, ip: str, exposed: bool = True) -> str:
        return self.add_node(NodeData(
            node_id=ip, node_type=NodeType.IP,
            label=ip, exposed=exposed,
        ))

    def add_port(self, ip: str, port: int, protocol: str = "tcp") -> str:
        port_id = f"{ip}:{port}/{protocol}"
        self.add_node(NodeData(
            node_id=port_id, node_type=NodeType.PORT,
            label=f"{port}/{protocol}", exposed=True,
            meta={"port": port, "protocol": protocol},
        ))
        self.add_edge(EdgeData(
            source=ip, target=port_id,
            edge_type=EdgeType.EXPOSES,
        ))
        return port_id

    def add_service(self, port_id: str, name: str, version: str = "") -> str:
        svc_id = f"svc:{name}@{port_id}"
        self.add_node(NodeData(
            node_id=svc_id, node_type=NodeType.SERVICE,
            label=name, exposed=True,
            meta={"version": version},
        ))
        self.add_edge(EdgeData(
            source=svc_id, target=port_id,
            edge_type=EdgeType.RUNS_ON,
        ))
        return svc_id

    def add_technology(self, asset_id: str, tech_name: str, version: str = "") -> str:
        tech_id = f"tech:{tech_name}"
        if tech_id not in self.G:
            self.add_node(NodeData(
                node_id=tech_id, node_type=NodeType.TECHNOLOGY,
                label=tech_name, meta={"version": version},
            ))
        self.add_edge(EdgeData(
            source=asset_id, target=tech_id,
            edge_type=EdgeType.USES,
        ))
        return tech_id

    def add_cve(self, asset_id: str, cve_id: str, cvss: float, description: str = "") -> str:
        if cve_id not in self.G:
            self.add_node(NodeData(
                node_id=cve_id, node_type=NodeType.CVE,
                label=cve_id, risk_score=cvss,
                meta={"cvss": cvss, "description": description},
            ))
        self.add_edge(EdgeData(
            source=asset_id, target=cve_id,
            edge_type=EdgeType.IS_VULNERABLE_TO,
        ))
        return cve_id

    def link_domain_to_ip(self, domain: str, ip: str) -> None:
        self.add_edge(EdgeData(
            source=domain, target=ip,
            edge_type=EdgeType.RESOLVES_TO,
        ))

    # ------------------------------------------------------------------
    # Graph analysis
    # ------------------------------------------------------------------

    def degree_centrality(self) -> dict[str, float]:
        """
        Nodes with many connections. High degree = wide blast radius.
        """
        if self.G.number_of_nodes() == 0:
            return {}
        try:
            return nx.degree_centrality(self.G)
        except Exception as e:
            log.warning("Degree centrality calculation failed: %s", e)
            return {n: 0.0 for n in self.G.nodes}

    def betweenness_centrality(self) -> dict[str, float]:
        """
        Nodes that act as bridges on many shortest paths.
        Compromising these disrupts the most routes.
        """
        if self.G.number_of_nodes() == 0:
            return {}
        try:
            return nx.betweenness_centrality(self.G, normalized=True)
        except Exception as e:
            log.warning("Betweenness centrality calculation failed: %s", e)
            return {n: 0.0 for n in self.G.nodes}

    def pagerank(self, alpha: float = 0.85) -> dict[str, float]:
        """
        PageRank treats edges as 'trust transfers'.
        High PageRank = many important nodes point to this one.
        """
        if self.G.number_of_nodes() == 0:
            return {}
        try:
            return nx.pagerank(self.G, alpha=alpha)
        except Exception as e:
            log.warning("PageRank calculation failed: %s. Falling back to uniform rank.", e)
            nodes = list(self.G.nodes)
            if not nodes:
                return {}
            val = 1.0 / len(nodes)
            return {n: val for n in nodes}

    def resolve_node_id(self, name: str) -> Optional[str]:
        """
        Find the real node ID for a name the caller supplied.

        Node IDs are case-sensitive strings, so ``"cve-2023-38408"`` would not
        match the stored ``"CVE-2023-38408"``. This looks for, in order:

            1. an exact match
            2. a case-insensitive match on the node ID
            3. a case-insensitive match on the node's label

        Returns ``None`` if nothing matches.
        """
        if not name:
            return None

        name = str(name).strip()
        if name in self.G:
            return name

        lowered = name.lower()
        for node_id in self.G.nodes:
            if str(node_id).lower() == lowered:
                return node_id

        for node_id, attrs in self.G.nodes(data=True):
            if str(attrs.get("label", "")).lower() == lowered:
                return node_id

        return None

    def attack_view(self) -> nx.DiGraph:
        """
        The graph re-pointed the way an *attacker* moves through it.

        Edges in this graph describe relationships, not routes. A service
        points at the port it runs on ("nginx runs on port 80"), and a
        subdomain points at its parent domain. An attacker travels the other
        way: they find the open port first and discover the service behind it
        second.

        That mismatch means a port node has no outgoing edges at all, so a
        directed search from a domain dead-ends at the first port and can never
        reach the service, technology or CVE beyond it.

        This view flips the edge types that are modelled backwards:

            domain    -> subdomain   (was subdomain -> domain)
            port      -> service     (was service -> port)

        and leaves the rest alone (including subdomain -> ip), giving a graph
        where a path really does represent a sequence of steps an attacker could take.
        """
        cache_key = (self.G.number_of_nodes(), self.G.number_of_edges())
        if self._attack_view_cache and self._attack_view_cache[0] == cache_key:
            return self._attack_view_cache[1]

        view = nx.DiGraph()
        view.add_nodes_from(self.G.nodes(data=True))

        for source, target, data in self.G.edges(data=True):
            edge_type   = data.get("edge_type", "")
            source_type = self.G.nodes[source].get("node_type", "")
            target_type = self.G.nodes[target].get("node_type", "")

            # Only reverse subdomain -> domain (parent). DO NOT reverse subdomain -> ip.
            reversed_edge = (
                edge_type == EdgeType.RUNS_ON.value
                or (edge_type == EdgeType.RESOLVES_TO.value
                    and source_type == NodeType.SUBDOMAIN.value
                    and target_type == NodeType.DOMAIN.value)
            )

            if reversed_edge:
                view.add_edge(target, source, **data)
            else:
                view.add_edge(source, target, **data)

        self._attack_view_cache = (cache_key, view)
        return view

    def shortest_attack_path(self, source: str, target: str,
                             follow_attack_direction: bool = True) -> Optional[list[str]]:
        """
        Returns the shortest path (list of node IDs) from source to target,
        or None if no path exists.

        Args:
            source: starting node - usually a domain, i.e. the public internet
            target: the node the attacker is trying to reach
            follow_attack_direction:
                When True (the default) the search runs over :meth:`attack_view`,
                so the path describes how an attacker actually moves. Pass
                False to search the raw relationship graph instead.

        Both node names are looked up with :meth:`resolve_node_id`, so
        ``"cve-2023-38408"`` and ``"CVE-2023-38408"`` both work.
        """
        source_id = self.resolve_node_id(source)
        target_id = self.resolve_node_id(target)

        if source_id is None:
            log.warning("Attack path: no node matching source '%s'", source)
            return None
        if target_id is None:
            log.warning("Attack path: no node matching target '%s'", target)
            return None

        search_graph = self.attack_view() if follow_attack_direction else self.G

        try:
            return nx.shortest_path(search_graph, source=source_id, target=target_id)
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return None

    def top_risk_nodes(self, top_n: int = 10) -> list[dict]:
        """
        Combines betweenness centrality with the node's own risk_score
        to produce a ranked list of the most critical assets.
        """
        if self.G.number_of_nodes() == 0:
            return []
        bc  = self.betweenness_centrality()
        pr  = self.pagerank()

        scored = []
        for nid, attrs in self.G.nodes(data=True):
            node_risk  = attrs.get("risk_score", 0.0)          # from CVE/manual
            topo_score = bc.get(nid, 0) * 5 + pr.get(nid, 0) * 5  # topology
            combined   = round((node_risk + topo_score) / 2, 3)
            scored.append({
                "node_id":    nid,
                "label":      attrs.get("label", nid),
                "node_type":  attrs.get("node_type"),
                "risk_score": node_risk,
                "topo_score": round(topo_score, 3),
                "combined":   combined,
                "exposed":    attrs.get("exposed", False),
            })

        return sorted(scored, key=lambda x: x["combined"], reverse=True)[:top_n]

    def exposed_nodes(self) -> list[str]:
        """Returns all node IDs where exposed=True."""
        return [n for n, d in self.G.nodes(data=True) if d.get("exposed")]

    def nodes_by_type(self, node_type: NodeType) -> list[str]:
        return [n for n, d in self.G.nodes(data=True)
                if d.get("node_type") == node_type.value]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        type_counts: dict[str, int] = {}
        for _, attrs in self.G.nodes(data=True):
            t = attrs.get("node_type", "unknown")
            type_counts[t] = type_counts.get(t, 0) + 1

        return {
            "target":       self.target,
            "total_nodes":  self.G.number_of_nodes(),
            "total_edges":  self.G.number_of_edges(),
            "node_types":   type_counts,
            "exposed_count": len(self.exposed_nodes()),
            "is_connected": nx.is_weakly_connected(self.G) if self.G.number_of_nodes() > 0 else False,
        }

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """Serialize the graph to a JSON-serializable dict (for the API/frontend)."""
        return {
            "nodes": [
                {"id": n, **{k: v for k, v in d.items()}}
                for n, d in self.G.nodes(data=True)
            ],
            "edges": [
                {"source": u, "target": v, **d}
                for u, v, d in self.G.edges(data=True)
            ],
        }

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            json.dump(self.to_dict(), f, indent=2)
        log.info("Graph saved to %s", path)

    @classmethod
    def load(cls, path: str) -> "AttackSurfaceGraph":
        with open(path) as f:
            data = json.load(f)

        # Rebuild — we need a target name; pull from first domain node or use filename
        target = next(
            (n["id"] for n in data["nodes"] if n.get("node_type") == "domain"),
            path,
        )
        g = cls(target=target)
        for node in data["nodes"]:
            nid = node.pop("id")
            g.G.add_node(nid, **node)
        for edge in data["edges"]:
            g.G.add_edge(edge["source"], edge["target"],
                         **{k: v for k, v in edge.items() if k not in ("source", "target")})
        log.info("Graph loaded from %s (%d nodes)", path, g.G.number_of_nodes())
        return g
