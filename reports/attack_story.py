"""
reports/attack_story.py
-----------------------
The "attack path storytelling" engine.

Phase 1 (``plain_english.py``) answers *what is wrong*. This module answers the
question a business owner asks straight afterwards:

    "OK... but how would someone actually break in?"

It walks the attack surface graph from a public entry point (your domain) to
the most dangerous thing it can reach, then retells that route as a short
numbered story with no jargon in it:

    HOW AN ATTACKER COULD BREACH YOU
    Step 1: An attacker finds admin.acme.com in seconds using free tools.
    Step 2: A port scan shows the MySQL database door open on port 3306.
    Step 3: That software has a publicly known weakness that lets an attacker
            skip the login screen entirely.
    Step 4: The attacker now has access to your database.
    Step 5: From there they can copy your entire customer list.

    BREACH PROBABILITY: High
    STEPS TO PREVENT THIS: ...

A note on direction
-------------------
``AttackSurfaceGraph`` models edges as relationships, not as attacker
movement: a *service* points at the *port* it runs on, while an *IP* points at
the ports it exposes. A directed search therefore dead-ends at a port node and
never reaches a service or a weakness behind it.

So this module calls the existing ``shortest_attack_path()`` first (it is the
right entry point, and it will start succeeding once the Phase 4 fix lands),
and falls back to an "attack direction" view of the same graph when it returns
nothing. No existing code is modified here.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from reports.plain_english import (
    PORT_PROFILES,
    Severity,
    _attrs,
    _capitalise,
    _host_for_asset,
    _label,
    _meta,
    _node_type,
    _safe_float,
    _safe_int,
    _wrap,
    cvss_to_severity,
    describe_subdomain,
    describe_vulnerability,
    friendly_name,
)

log = logging.getLogger(__name__)


#: Ports that hand an attacker something valuable the moment they get through.
CROWN_JEWEL_PORTS = {
    1433: "your customer and business records",
    3306: "your customer and business records",
    5432: "your customer and business records",
    27017: "your application's records",
    9200: "a full searchable copy of your business data",
    6379: "the login sessions of everyone using your site",
    3389: "a full desktop on your server, exactly as your staff would see it",
    445:  "every file on your shared drives",
    139:  "every file on your shared drives",
    5900: "a live view of the screen, as if they were sitting at the machine",
    22:   "direct command-line control of the server",
    23:   "direct command-line control of the server",
    21:   "the files stored on your file transfer server",
}

#: What an attacker does *next*, once they own a given kind of asset.
ESCALATION_BY_ROLE: list[tuple[tuple[str, ...], str]] = [
    (("database", "customer records", "records"),
     "copy your entire customer list, then demand payment not to publish it"),
    (("email", "mail"),
     "read every email your business has sent, and send convincing fake invoices "
     "from your own address to your customers"),
    (("admin", "control panel", "hosting control"),
     "add themselves a permanent administrator account, so they still have access "
     "long after you change your passwords"),
    (("website server", "web application", "website"),
     "install ransomware on the server, redirect your customers to a fake payment "
     "page, or quietly sit on your systems for months"),
    (("file transfer", "file sharing"),
     "download every file your staff have shared, including contracts and payroll"),
    (("remote control", "remote desktop", "remote access"),
     "move from that one machine onto every other computer in your office"),
    (("source code",),
     "read the passwords and keys that are almost always left inside source code"),
    (("backup",),
     "restore a complete copy of your business data onto their own machine"),
    (("session", "cache"),
     "log in as any of your customers or staff without needing their password"),
]


# ===========================================================================
# Story data structures
# ===========================================================================

@dataclass
class StoryStep:
    """One numbered line of the narrative, plus the technical fact behind it."""

    number: int
    text: str
    node_id: str = ""
    technical: str = ""

    def to_dict(self) -> dict:
        return {
            "number":    self.number,
            "text":      self.text,
            "node_id":   self.node_id,
            "technical": self.technical,
        }


@dataclass
class AttackStory:
    """
    One complete "here is how someone gets in" narrative.

    Attributes:
        title              : one-line summary of the route
        target_asset       : plain English name of what the attacker reaches
        steps              : the numbered narrative
        breach_probability : High / Medium / Low
        probability_reason : one sentence explaining that rating
        prevention_steps   : concrete actions that break this specific path
        severity           : CRITICAL / HIGH / MEDIUM / LOW
        max_cvss           : worst CVSS score anywhere on the path
        path               : the raw graph node IDs (technical, for IT)
    """

    title: str
    target_asset: str
    steps: list[StoryStep]
    breach_probability: str
    probability_reason: str
    prevention_steps: list[str]
    severity: str = Severity.MEDIUM
    max_cvss: float = 0.0
    path: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "title":              self.title,
            "target_asset":       self.target_asset,
            "steps":              [s.to_dict() for s in self.steps],
            "breach_probability": self.breach_probability,
            "probability_reason": self.probability_reason,
            "prevention_steps":   list(self.prevention_steps),
            "severity":           self.severity,
            "max_cvss":           self.max_cvss,
            "path":               list(self.path),
        }

    def to_text(self, width: int = 78) -> str:
        """Render the story exactly as a business owner should read it."""
        out: list[str] = []
        out.append(_wrap(f"HOW AN ATTACKER COULD BREACH YOU: {self.title}",
                         width, "  ", first="  "))
        out.append("")
        for step in self.steps:
            out.append(_wrap(f"Step {step.number}: {step.text}",
                             width, "          ", first="  "))
        out.append("")
        out.append(_wrap(f"BREACH PROBABILITY: {self.breach_probability} "
                         f"- {self.probability_reason}", width, "      ", first="  "))
        out.append("")
        out.append("  STEPS TO PREVENT THIS:")
        for i, action in enumerate(self.prevention_steps, 1):
            out.append(_wrap(f"{i}. {action}", width, "       ", first="    "))
        return "\n".join(out)

    def __str__(self) -> str:                     # pragma: no cover - convenience
        return self.to_text()


# ===========================================================================
# Attack-direction view of the graph
# ===========================================================================

def build_attack_view(graph):
    """
    Return a copy of the graph with every edge pointing the way an *attacker*
    moves, rather than the way the relationship reads.

    The relationship model in builder.py says "this service runs on that port".
    An attacker travels the other way: they find the port first, and the
    service behind it second. Same for a subdomain, which is modelled as
    pointing at its parent domain.

    Rules:
        domain    -> subdomain   (attacker enumerates your addresses)
        domain    -> ip          (the address resolves to a server)
        ip        -> port        (a scan finds open doors)
        port      -> service     (the door answers with some software)
        service   -> technology  (the software is built on something)
        anything  -> cve         (that thing has a known weakness)
    """
    import networkx as nx

    view = nx.DiGraph()
    view.add_nodes_from(graph.G.nodes(data=True))

    for source, target, data in graph.G.edges(data=True):
        edge_type   = data.get("edge_type", "")
        source_type = _node_type(graph, source)
        target_type = _node_type(graph, target)

        # A subdomain points at its parent domain; an attacker goes the other way.
        if edge_type == "resolves_to" and source_type == "subdomain" and target_type == "domain":
            view.add_edge(target, source, **data)
        # A service points at its port; an attacker reaches the port first.
        elif edge_type == "runs_on":
            view.add_edge(target, source, **data)
        else:
            view.add_edge(source, target, **data)

    return view


def _find_path(graph, attack_view, source: str, target: str) -> Optional[list[str]]:
    """
    Find a route from ``source`` to ``target``.

    Tries the project's own ``shortest_attack_path()`` first so this module
    keeps using the documented API, then falls back to the attack-direction
    view (see the module docstring for why that is currently necessary).
    """
    try:
        path = graph.shortest_attack_path(source, target)
        if path:
            return list(path)
    except Exception as exc:                      # pragma: no cover - defensive
        log.debug("shortest_attack_path(%s, %s) failed: %s", source, target, exc)

    try:
        import networkx as nx
        return list(nx.shortest_path(attack_view, source=source, target=target))
    except Exception:
        return None


# ===========================================================================
# Picking entry points and targets
# ===========================================================================

def internet_entry_points(graph) -> list[str]:
    """
    Where an attack starts: your domain, and any address exposed publicly.

    The main domain is preferred, because that is what an attacker types in
    first and it makes for the most honest story.
    """
    domains = [
        n for n, d in graph.G.nodes(data=True)
        if d.get("node_type") == "domain"
    ]
    subdomains = [
        n for n, d in graph.G.nodes(data=True)
        if d.get("node_type") == "subdomain" and d.get("exposed", True)
    ]
    return domains + subdomains


def _target_danger(graph, node_id: str, attrs: dict) -> tuple[float, str]:
    """
    How valuable is this node to an attacker? Returns ``(score, reason)``.

    Scores are on the familiar 0-10 scale so they line up with CVSS, which
    keeps the ranking easy to reason about.
    """
    node_type = attrs.get("node_type", "")

    if node_type == "cve" or str(node_id).upper().startswith("CVE-"):
        cvss = _safe_float(_meta(graph, node_id).get("cvss"),
                           _safe_float(attrs.get("risk_score")))
        return cvss, "a publicly known weakness in software you run"

    if node_type == "port":
        port = _safe_int(_meta(graph, node_id).get("port"))
        if port in CROWN_JEWEL_PORTS:
            profile = PORT_PROFILES.get(port, {})
            base = 9.5 if profile.get("severity") == Severity.CRITICAL else 7.5
            return base, CROWN_JEWEL_PORTS[port]
        return 0.0, ""

    if node_type == "subdomain":
        role, should_be_public, _concern = describe_subdomain(_label(graph, node_id))
        if not should_be_public:
            base = 8.5 if any(w in role for w in ("admin", "database", "backup")) else 7.0
            return base, role
        return 0.0, ""

    return 0.0, ""


def _rank_targets(graph) -> list[tuple[str, float, str]]:
    """Everything worth breaking into, worst first."""
    targets: list[tuple[str, float, str]] = []
    for node_id, attrs in graph.G.nodes(data=True):
        score, reason = _target_danger(graph, node_id, attrs)
        if score > 0:
            targets.append((node_id, score, reason))
    return sorted(targets, key=lambda t: t[1], reverse=True)


# ===========================================================================
# Narration — turning a list of node IDs into sentences
# ===========================================================================

def _narrate_node(graph, node_id: str, position: int, is_first: bool) -> Optional[str]:
    """
    One sentence describing what the attacker learns or gains at this hop.

    Returns ``None`` for hops that add nothing worth telling a business owner
    (for example a technology node that just repeats the service).
    """
    node_type = _node_type(graph, node_id)
    label = _label(graph, node_id)

    if node_type == "domain":
        if is_first:
            return (
                f"An attacker starts with the one thing everybody knows about your "
                f"business: your web address, {label}."
            )
        return f"They follow the trail back to your main address, {label}."

    if node_type == "subdomain":
        role, should_be_public, _concern = describe_subdomain(label)
        if is_first:
            return (
                f"An attacker finds {label} in a few seconds. Every address a company "
                f"owns is listed in public records that anyone can search for free."
            )
        if not should_be_public:
            return (
                f"Among your addresses they spot {label} - {role}, which was never "
                f"meant to be found by the public."
            )
        return f"They follow {label} to see what is behind it."

    if node_type == "ip":
        return f"That address points at one of your servers, {label}."

    if node_type == "port":
        port    = _safe_int(_meta(graph, node_id).get("port"))
        profile = PORT_PROFILES.get(port)
        host    = _host_for_asset(graph, node_id) or "the server"
        if profile:
            return (
                f"A quick scan of that server shows the {profile['name']} door "
                f"standing open on port {port}. This takes under a minute and "
                f"leaves almost no trace."
            )
        return (
            f"A quick scan of {host} shows port {port} standing open, which anyone "
            f"on the internet can connect to."
        )

    if node_type == "service":
        role    = friendly_name(graph, node_id)
        version = _meta(graph, node_id).get("version", "")
        if version:
            return (
                f"The door answers and identifies itself: {role}. That reply tells "
                f"the attacker the exact version, so they know precisely which "
                f"weaknesses to try."
            )
        return f"The door answers, revealing that it is {role}."

    if node_type == "technology":
        return f"They can see the software behind it is {label}."

    if node_type == "cve" or str(node_id).upper().startswith("CVE-"):
        meta = _meta(graph, node_id)
        cvss = _safe_float(meta.get("cvss"), _safe_float(_attrs(graph, node_id).get("risk_score")))
        what_it_does, _gain = describe_vulnerability(meta.get("description", ""), cvss)
        return (
            f"That exact version has a weakness that is public knowledge, and it "
            f"{what_it_does}. Ready-made tools for this are free to download."
        )

    return None


def _escalation_for(graph, node_id: str, target_reason: str, consequence: str = "") -> str:
    """
    What the attacker does after they are in — the last step of the story.

    The consequence is included in the search text because a path that ends on
    a weakness tells us nothing by itself; what matters is the *thing* that
    weakness sits on, which is what the consequence names.
    """
    haystack = " ".join([
        consequence,
        friendly_name(graph, node_id),
        target_reason,
        _host_for_asset(graph, node_id),
    ]).lower()

    for keywords, escalation in ESCALATION_BY_ROLE:
        if any(k in haystack for k in keywords):
            return escalation

    return (
        "use that foothold to reach the rest of your network, because most small "
        "business systems trust each other once an attacker is inside"
    )


def _consequence_for(graph, path: list[str], target_reason: str) -> str:
    """
    Plain English answer to "so what have they got?" — used for the
    "Attacker now has access to ..." step.
    """
    # Walk backwards for the most meaningful thing on the path.
    for node_id in reversed(path):
        node_type = _node_type(graph, node_id)
        if node_type == "port":
            port = _safe_int(_meta(graph, node_id).get("port"))
            if port in CROWN_JEWEL_PORTS:
                return CROWN_JEWEL_PORTS[port]
        if node_type == "service":
            # Drop the "(nginx version 1.14.0)" part — by this point in the
            # story the owner already knows which software it is, and the
            # version number adds nothing to "what have they got?".
            return friendly_name(graph, node_id).split(" (")[0]
        if node_type == "subdomain":
            role, should_be_public, _c = describe_subdomain(_label(graph, node_id))
            if not should_be_public:
                return role

    return target_reason or "your server"


# ===========================================================================
# Breach probability
# ===========================================================================

def _breach_probability(graph, path: list[str], max_cvss: float) -> tuple[str, str]:
    """
    Rate how likely this route is, and explain the rating in one sentence a
    business owner can weigh up.

    Three things drive the rating:

    * **A known weakness** removes the need for any skill — the attacker
      downloads a tool and runs it.
    * **A short path** matters because every extra hop is one more thing that
      has to go right for the attacker.
    * **What is sitting at the end**: an unprotected database or an admin panel
      needs no vulnerability at all, just a guessed password.
    """
    hops = max(len(path) - 1, 1)
    score = 0

    # 1. Is there a published weakness to exploit? A top-severity one usually
    #    means a working tool already exists, so it counts for a lot.
    if max_cvss >= 9.0:
        score += 4
    elif max_cvss >= 7.0:
        score += 2
    elif max_cvss >= 4.0:
        score += 1

    # 2. How far in is it?
    if hops <= 2:
        score += 2
    elif hops <= 4:
        score += 1

    # 3. How valuable and how unprotected is the destination? Take the single
    #    most attractive thing anywhere on the route, not the sum, so a long
    #    path through several assets is not over-rated.
    exposure = 0
    for node_id in path:
        node_type = _node_type(graph, node_id)

        if node_type == "port":
            port = _safe_int(_meta(graph, node_id).get("port"))
            if port in CROWN_JEWEL_PORTS:
                profile = PORT_PROFILES.get(port, {})
                exposure = max(exposure, 3 if profile.get("severity") == Severity.CRITICAL else 2)

        elif node_type == "subdomain":
            role, should_be_public, _c = describe_subdomain(_label(graph, node_id))
            if not should_be_public:
                exposure = max(
                    exposure,
                    2 if any(w in role for w in ("admin", "database", "backup",
                                                 "hosting control")) else 1,
                )
    score += exposure

    steps_txt     = f"{hops} step{'s' if hops != 1 else ''}"
    has_weakness  = max_cvss >= 7.0

    if score >= 5:
        level = "High"
        reason = (
            f"ready-made tools for this are free to download, and the route is only "
            f"{steps_txt} long"
            if has_weakness else
            f"the way in is only {steps_txt} long and the last door is left open to "
            f"everyone on the internet"
        )
    elif score >= 3:
        level = "Medium"
        reason = (
            f"published tools exist for this, but the attacker still has to line up "
            f"{steps_txt} to use them"
            if has_weakness else
            f"the route is short at {steps_txt}, but the attacker still has to get "
            f"past a password to use it"
        )
    else:
        level = "Low"
        reason = (
            "this would take real skill and patience, but it is still a genuine route in"
        )

    return level, reason


# ===========================================================================
# Prevention advice
# ===========================================================================

def _prevention_steps(graph, path: list[str]) -> list[str]:
    """
    Concrete actions that break *this specific* path.

    Ordered by where they sit on the route, so the first suggestion is the
    earliest place the attacker can be stopped — the cheapest place to fix.
    """
    actions: list[str] = []

    def add(action: str) -> None:
        action = " ".join(str(action).split())
        if action and action not in actions:
            actions.append(action)

    for node_id in path:
        node_type = _node_type(graph, node_id)

        if node_type == "subdomain":
            label = _label(graph, node_id)
            role, should_be_public, _c = describe_subdomain(label)
            if not should_be_public:
                add(f"Take {label} off the public internet, or restrict it to your "
                    f"office IP address. If nobody uses it any more, remove it entirely.")

        elif node_type == "port":
            port    = _safe_int(_meta(graph, node_id).get("port"))
            profile = PORT_PROFILES.get(port)
            if profile and not (profile["public_ok"] and profile["severity"] == Severity.LOW):
                add(profile["action"])

        elif node_type == "service":
            version = _meta(graph, node_id).get("version", "")
            name    = _label(graph, node_id)
            if version:
                add(f"Update {name} (currently version {version}) to the latest version.")
            else:
                add(f"Make sure {name} is on the latest version and set it to update "
                    f"automatically.")

        elif node_type == "cve" or str(node_id).upper().startswith("CVE-"):
            add("Apply the security updates for this software. The fix is already "
                "published by the vendor - it just has not been installed yet.")

    add("Turn on two-step login for every account that can administer these systems.")
    return actions[:6]


# ===========================================================================
# Building the stories
# ===========================================================================

def _path_max_cvss(graph, path: list[str]) -> float:
    """Worst CVSS score anywhere along the route."""
    worst = 0.0
    for node_id in path:
        if _node_type(graph, node_id) == "cve" or str(node_id).upper().startswith("CVE-"):
            meta = _meta(graph, node_id)
            cvss = _safe_float(meta.get("cvss"),
                               _safe_float(_attrs(graph, node_id).get("risk_score")))
            worst = max(worst, cvss)
    return worst


def narrate_path(graph, path: list[str], target_reason: str = "") -> Optional[AttackStory]:
    """
    Turn a list of graph node IDs into a finished :class:`AttackStory`.

    Returns ``None`` if the path is too short to tell a meaningful story.
    """
    if not path or len(path) < 2:
        return None

    steps: list[StoryStep] = []
    number = 0

    for position, node_id in enumerate(path):
        sentence = _narrate_node(graph, node_id, position, is_first=(position == 0))
        if not sentence:
            continue
        number += 1
        steps.append(StoryStep(
            number=number,
            text=sentence,
            node_id=node_id,
            technical=f"{_node_type(graph, node_id) or 'node'}: {node_id}",
        ))

    if not steps:
        return None

    # "Attacker now has access to ..." and "From there they can ..."
    consequence = _consequence_for(graph, path, target_reason)
    number += 1
    steps.append(StoryStep(
        number=number,
        text=f"At this point the attacker has access to {consequence}.",
        node_id=path[-1],
        technical=f"objective reached: {path[-1]}",
    ))

    number += 1
    steps.append(StoryStep(
        number=number,
        text=(f"From there they can "
              f"{_escalation_for(graph, path[-1], target_reason, consequence)}."),
        node_id=path[-1],
        technical="post-compromise escalation",
    ))

    max_cvss = _path_max_cvss(graph, path)
    probability, reason = _breach_probability(graph, path, max_cvss)

    entry_label  = _label(graph, path[0])
    target_asset = friendly_name(graph, path[-1])
    if _node_type(graph, path[-1]) == "cve":
        target_asset = _consequence_for(graph, path, target_reason)

    # Severity reflects the worst of "how bad is the weakness" and "how
    # valuable is the thing at the end". A wide open database with no known
    # CVE is still a critical story, so CVSS alone is not enough.
    target_score, _reason = _target_danger(graph, path[-1], _attrs(graph, path[-1]))
    severity = cvss_to_severity(max(max_cvss, target_score))
    if probability == "High" and severity in (Severity.MEDIUM, Severity.LOW):
        severity = Severity.HIGH

    return AttackStory(
        title=f"from {entry_label} to {target_asset}",
        target_asset=target_asset,
        steps=steps,
        breach_probability=probability,
        probability_reason=reason,
        prevention_steps=_prevention_steps(graph, path),
        severity=severity,
        max_cvss=max_cvss,
        path=list(path),
    )


def generate_stories(graph, top_n: int = 3) -> list[AttackStory]:
    """
    Find the ``top_n`` most dangerous routes into the business and narrate them.

    Routes are chosen worst-first, but deliberately spread across *different*
    assets: three stories about the same database teaches the owner nothing.
    Any single failure is logged and skipped rather than losing the whole set.
    """
    stories: list[AttackStory] = []

    try:
        entries = internet_entry_points(graph)
        if not entries:
            log.warning("No public entry point found - cannot build attack stories.")
            return []

        attack_view = build_attack_view(graph)
        targets     = _rank_targets(graph)
        used_hosts: set[str] = set()

        for target_id, _score, reason in targets:
            if len(stories) >= top_n:
                break

            # Keep the three stories about three different parts of the business.
            host = _host_for_asset(graph, target_id) or target_id
            if host in used_hosts:
                continue

            best: Optional[list[str]] = None
            for entry in entries:
                if entry == target_id:
                    continue
                path = _find_path(graph, attack_view, entry, target_id)
                if path and (best is None or len(path) < len(best)):
                    best = path

            if not best:
                continue

            try:
                story = narrate_path(graph, best, target_reason=reason)
            except Exception as exc:
                log.error("Could not narrate path to %s: %s", target_id, exc)
                continue

            if story:
                stories.append(story)
                used_hosts.add(host)

    except Exception as exc:
        log.error("Attack story generation failed: %s", exc)

    return stories


def generate_story_report(graph, top_n: int = 3) -> dict:
    """JSON-serialisable bundle of stories, for the API, PDF and email alerts."""
    stories = generate_stories(graph, top_n=top_n)
    return {
        "target":       getattr(graph, "target", "") or "",
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "story_count":  len(stories),
        "worst_probability": (
            stories[0].breach_probability if stories else "Low"
        ),
        "stories": [s.to_dict() for s in stories],
    }


# ===========================================================================
# Text rendering
# ===========================================================================

def format_stories_text(stories: list[AttackStory], width: int = 78) -> str:
    """Render the stories for the terminal. ASCII only, for the Windows console."""
    rule = "=" * width
    out: list[str] = [rule, "  HOW SOMEONE COULD BREAK INTO YOUR BUSINESS", rule, ""]

    if not stories:
        out.append(_wrap(
            "We could not trace a complete route into your systems from this scan. "
            "That is a good sign, but it is not a guarantee - it may also mean the "
            "scan did not get far enough to see one.", width, "  ", first="  "))
        out.append("")
        out.append(rule)
        return "\n".join(out)

    for i, story in enumerate(stories, 1):
        out.append(f"  ATTACK PATH {i} of {len(stories)}  [{story.severity}]")
        out.append("  " + "-" * (width - 4))
        out.append(story.to_text(width=width))
        out.append("")

    out.append(rule)
    return "\n".join(out)


def print_stories(graph, top_n: int = 3) -> list[AttackStory]:
    """Convenience: build the stories, print them, hand them back."""
    stories = generate_stories(graph, top_n=top_n)
    print(format_stories_text(stories))
    return stories


# ===========================================================================
# CLI:  python -m reports.attack_story attack_surface.json
# ===========================================================================

if __name__ == "__main__":
    import argparse

    from graph.builder import AttackSurfaceGraph

    parser = argparse.ArgumentParser(
        description="Turn a SurfaceWatch scan into plain English attack stories."
    )
    parser.add_argument("scan_file", nargs="?", default="attack_surface.json",
                        help="Path to a saved scan JSON file")
    parser.add_argument("--top", type=int, default=3,
                        help="How many attack paths to tell (default: 3)")
    parser.add_argument("--json", action="store_true",
                        help="Print as JSON instead of text")
    args = parser.parse_args()

    try:
        loaded_graph = AttackSurfaceGraph.load(args.scan_file)
    except FileNotFoundError:
        raise SystemExit(f"Scan file not found: {args.scan_file}")
    except Exception as error:
        raise SystemExit(f"Could not read scan file '{args.scan_file}': {error}")

    if args.json:
        import json
        print(json.dumps(generate_story_report(loaded_graph, top_n=args.top), indent=2))
    else:
        print(format_stories_text(generate_stories(loaded_graph, top_n=args.top)))
