"""
reports/plain_english.py
------------------------
The "translation layer" of SurfaceWatch.

Everything the scanners and the graph produce is technical: CVE identifiers,
CVSS vectors, node IDs like ``svc:nginx@192.124.249.6:80/tcp``, and graph
metrics like betweenness centrality. A small business owner cannot act on any
of that.

This module reads an :class:`~graph.builder.AttackSurfaceGraph` and produces
plain English *findings*. Each finding answers four questions a business owner
actually asks:

    1. What is exposed?
    2. Why does that matter to my business?
    3. How could a criminal use it?
    4. What exactly do I do about it?

No CVE IDs, no CVSS vectors, and no graph jargon appear in the plain English
text. The technical details are still carried along on each finding (in
``Finding.evidence``) so the business owner can hand them to an IT person, but
they are never part of the sentences they read.

Typical use::

    from graph.builder import AttackSurfaceGraph
    from reports.plain_english import generate_report, format_report_text

    graph  = AttackSurfaceGraph.load("attack_surface.json")
    report = generate_report(graph)
    print(format_report_text(report))

This module is deliberately dependency-free (standard library + NetworkX via
the graph object) so it can be imported by the CLI, the Flask API, the PDF
generator and the email alerter without pulling anything else in.
"""

from __future__ import annotations

import logging
import textwrap
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Optional

log = logging.getLogger(__name__)


# ===========================================================================
# Severity
# ===========================================================================

class Severity:
    """
    Plain English severity levels.

    Kept as a simple class of string constants (rather than an Enum) so that
    findings stay trivially JSON-serialisable for the API, the PDF generator
    and the email templates.
    """

    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"

    #: Ordering used for sorting — lower number = more urgent.
    ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3}

    #: Colours used by the PDF report and the HTML email template.
    COLORS = {
        CRITICAL: "#c0392b",   # red
        HIGH:     "#e67e22",   # orange
        MEDIUM:   "#f1c40f",   # yellow
        LOW:      "#27ae60",   # green
    }

    #: One-line explanation of what each level means to a business owner.
    MEANING = {
        CRITICAL: "Fix this today. A criminal could break in with little effort.",
        HIGH:     "Fix this within a week. This is a realistic way in.",
        MEDIUM:   "Plan to fix this. It helps an attacker, but not on its own.",
        LOW:      "Worth tidying up when you have time. Low real-world risk.",
    }

    @classmethod
    def sort_key(cls, severity: str) -> int:
        return cls.ORDER.get(severity, 99)


def cvss_to_severity(score: Optional[float]) -> str:
    """
    Convert a CVSS score (0.0-10.0) into a plain English severity level.

        9.0 - 10.0  -> CRITICAL
        7.0 -  8.9  -> HIGH
        4.0 -  6.9  -> MEDIUM
        0.1 -  3.9  -> LOW

    Anything missing, unparseable or 0.0 is treated as LOW so that a bad
    reading can never silently hide a finding.
    """
    try:
        value = float(score)
    except (TypeError, ValueError):
        return Severity.LOW

    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


# ===========================================================================
# Finding
# ===========================================================================

@dataclass
class Finding:
    """
    One thing that is wrong, described the way a business owner would want it
    described.

    Attributes:
        severity            : CRITICAL / HIGH / MEDIUM / LOW
        what_is_exposed     : one sentence, plain English
        why_it_matters      : one sentence, real-world business impact
        how_attacker_uses_it: one sentence, how a criminal would abuse it
        recommended_action  : one concrete step the owner (or their IT
                              person) can actually carry out
        asset               : plain English name of the affected thing
        node_id             : the underlying graph node (technical, not shown)
        cvss                : highest CVSS score behind this finding, if any
        category            : coarse grouping, e.g. "vulnerability", "exposure"
        evidence            : technical details for the IT person only
    """

    severity: str
    what_is_exposed: str
    why_it_matters: str
    how_attacker_uses_it: str
    recommended_action: str
    asset: str = ""
    node_id: str = ""
    cvss: float = 0.0
    category: str = "general"
    evidence: list[str] = field(default_factory=list)

    # -- rendering ---------------------------------------------------------

    def to_dict(self) -> dict:
        """JSON-serialisable form (used by the API, alerts and the PDF)."""
        return {
            "severity":             self.severity,
            "what_is_exposed":      self.what_is_exposed,
            "why_it_matters":       self.why_it_matters,
            "how_attacker_uses_it": self.how_attacker_uses_it,
            "recommended_action":   self.recommended_action,
            "asset":                self.asset,
            "node_id":              self.node_id,
            "cvss":                 self.cvss,
            "category":             self.category,
            "evidence":             list(self.evidence),
        }

    def to_text(self, width: int = 78, indent: str = "  ") -> str:
        """
        The labelled block format:

            SEVERITY: CRITICAL
            WHAT IS EXPOSED: ...
            WHY IT MATTERS: ...
            HOW AN ATTACKER COULD USE IT: ...
            RECOMMENDED ACTION: ...
        """
        rows = [
            ("SEVERITY",                     self.severity),
            ("WHAT IS EXPOSED",              self.what_is_exposed),
            ("WHY IT MATTERS",               self.why_it_matters),
            ("HOW AN ATTACKER COULD USE IT", self.how_attacker_uses_it),
            ("RECOMMENDED ACTION",           self.recommended_action),
        ]
        lines = []
        for label, value in rows:
            lines.append(_wrap(f"{label}: {value}", width=width,
                               indent=indent + "    ", first=indent))
        return "\n".join(lines)

    def to_paragraph(self, width: int = 78) -> str:
        """
        The short headline format, e.g.

            CRITICAL: Your admin panel (admin.yourdomain.com) is publicly
            accessible and runs software with 3 known weaknesses. An attacker
            could reach your customer database in 2 steps from the internet.
            RECOMMENDED ACTION: Restrict admin panel access to your office IP
            address only.
        """
        body = (
            f"{self.severity}: {self.what_is_exposed} {self.how_attacker_uses_it} "
            f"RECOMMENDED ACTION: {self.recommended_action}"
        )
        return _wrap(body, width=width, indent="  ")

    def __str__(self) -> str:  # pragma: no cover - convenience only
        return self.to_text()


def _wrap(text: str, width: int = 78, indent: str = "    ", first: str = "") -> str:
    """Wrap a line of prose, indenting the first and following lines."""
    return textwrap.fill(
        " ".join(str(text).split()),
        width=width,
        initial_indent=first,
        subsequent_indent=indent,
    )


# ===========================================================================
# Knowledge base — technical thing -> what it means to a business
# ===========================================================================

#: Subdomain prefixes and what they usually are in plain English.
#: (friendly role, is it meant to be public?, extra concern)
SUBDOMAIN_ROLES: dict[str, tuple[str, bool, str]] = {
    "admin":      ("your admin control panel",            False, "It controls your whole website."),
    "administrator": ("your admin control panel",         False, "It controls your whole website."),
    "manage":     ("your management console",             False, "It controls your whole website."),
    "portal":     ("your staff portal",                   False, "Staff accounts open the door to your data."),
    "intranet":   ("your internal staff site",            False, "It is meant for employees only."),
    "internal":   ("an internal-only system",             False, "It is meant for employees only."),
    "vpn":        ("your remote access (VPN) gateway",    True,  "It is the front door for remote staff."),
    "remote":     ("your remote access gateway",          True,  "It is the front door for remote staff."),
    "mail":       ("your email server",                   True,  "Email is how invoices and passwords travel."),
    "smtp":       ("your outgoing email server",          True,  "Email is how invoices and passwords travel."),
    "imap":       ("your email inbox server",             True,  "Email is how invoices and passwords travel."),
    "webmail":    ("your webmail login page",             True,  "Email is how invoices and passwords travel."),
    "mx":         ("your email routing server",           True,  "Email is how invoices and passwords travel."),
    "dev":        ("a development (work-in-progress) site", False, "Test sites are rarely kept up to date."),
    "dev2":       ("a second development site",           False, "Test sites are rarely kept up to date."),
    "test":       ("a test site",                         False, "Test sites are rarely kept up to date."),
    "testing":    ("a test site",                         False, "Test sites are rarely kept up to date."),
    "staging":    ("a staging (pre-release) copy of your site", False, "Staging copies often hold real customer data."),
    "stage":      ("a staging copy of your site",         False, "Staging copies often hold real customer data."),
    "uat":        ("a user-testing copy of your site",    False, "Test copies often hold real customer data."),
    "demo":       ("a demo site",                         False, "Demo sites are rarely kept up to date."),
    "beta":       ("a beta test site",                    False, "Beta sites are rarely kept up to date."),
    "old":        ("an old, retired site",                False, "Forgotten sites never get security updates."),
    "legacy":     ("a legacy (retired) system",           False, "Forgotten systems never get security updates."),
    "backup":     ("a backup system",                     False, "Backups contain a full copy of your data."),
    "bak":        ("a backup system",                     False, "Backups contain a full copy of your data."),
    "db":         ("a database server",                   False, "This is where your customer records live."),
    "database":   ("a database server",                   False, "This is where your customer records live."),
    "sql":        ("a database server",                   False, "This is where your customer records live."),
    "mysql":      ("a database server",                   False, "This is where your customer records live."),
    "postgres":   ("a database server",                   False, "This is where your customer records live."),
    "mongo":      ("a database server",                   False, "This is where your customer records live."),
    "redis":      ("a data cache server",                 False, "It often holds login sessions."),
    "ftp":        ("your file transfer server",           False, "It holds files staff share."),
    "files":      ("your file sharing server",            False, "It holds files staff share."),
    "share":      ("your file sharing server",            False, "It holds files staff share."),
    "git":        ("your source code server",             False, "Your code often contains passwords and keys."),
    "gitlab":     ("your source code server",             False, "Your code often contains passwords and keys."),
    "svn":        ("your source code server",             False, "Your code often contains passwords and keys."),
    "jenkins":    ("your software build server",          False, "Build servers hold keys to everything else."),
    "ci":         ("your software build server",          False, "Build servers hold keys to everything else."),
    "api":        ("your API (the service your apps talk to)", True, "Apps and partners depend on it."),
    "api2":       ("a second API service",                True,  "Apps and partners depend on it."),
    "app":        ("your web application",                True,  "Customers log in here."),
    "shop":       ("your online shop",                    True,  "Customers enter payment details here."),
    "store":      ("your online shop",                    True,  "Customers enter payment details here."),
    "pay":        ("your payment page",                   True,  "Customers enter payment details here."),
    "payment":    ("your payment page",                   True,  "Customers enter payment details here."),
    "checkout":   ("your checkout page",                  True,  "Customers enter payment details here."),
    "billing":    ("your billing system",                 False, "It holds invoices and payment records."),
    "crm":        ("your customer records system",        False, "It holds your entire customer list."),
    "hr":         ("your HR system",                      False, "It holds staff personal records."),
    "vpn2":       ("a second remote access gateway",      True,  "It is the front door for remote staff."),
    "cpanel":     ("your hosting control panel",          False, "It controls your website hosting account."),
    "whm":        ("your hosting control panel",          False, "It controls your website hosting account."),
    "phpmyadmin": ("your database admin page",            False, "It gives direct access to your data."),
    "monitor":    ("your monitoring dashboard",           False, "It maps out your internal systems."),
    "grafana":    ("your monitoring dashboard",           False, "It maps out your internal systems."),
    "kibana":     ("your log search dashboard",           False, "Logs often contain customer data."),
    "jira":       ("your project tracking system",        False, "Tickets often describe internal systems."),
    "wiki":       ("your internal wiki",                  False, "Wikis often contain passwords and procedures."),
    "docs":       ("your documentation site",             True,  ""),
    "blog":       ("your blog",                           True,  ""),
    "news":       ("your news site",                      True,  ""),
    "shop2":      ("a second online shop",                True,  ""),
    "cdn":        ("your content delivery service",       True,  ""),
    "static":     ("your static file server",             True,  ""),
    "img":        ("your image server",                   True,  ""),
    "images":     ("your image server",                   True,  ""),
    "assets":     ("your website asset server",           True,  ""),
    "www":        ("your main website",                   True,  ""),
    "web":        ("your main website",                   True,  ""),
    "ns":         ("one of your DNS name servers",        True,  ""),
    "ns1":        ("one of your DNS name servers",        True,  ""),
    "ns2":        ("one of your DNS name servers",        True,  ""),
}

#: Ports and what having them open on the public internet means.
#: Each entry: friendly name, should it normally be public, base severity,
#: why it matters, how an attacker uses it, what to do.
PORT_PROFILES: dict[int, dict[str, Any]] = {
    21: {
        "name": "file transfer (FTP)", "public_ok": False, "severity": Severity.HIGH,
        "why": "Old-style file transfer sends usernames and passwords in plain text that anyone on the network can read.",
        "attack": "An attacker can capture the password as it travels, or simply guess it, and then download or replace your files.",
        "action": "Turn off FTP and move file transfers to SFTP, or restrict it to your office IP address.",
    },
    22: {
        "name": "remote server login (SSH)", "public_ok": True, "severity": Severity.MEDIUM,
        "why": "This is the door administrators use to control the server directly.",
        "attack": "Automated bots try thousands of common passwords against this door every day.",
        "action": "Allow logins only with a key file (not a password), and limit access to your office IP address.",
    },
    23: {
        "name": "old remote control (Telnet)", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "Telnet is a decades-old technology that sends everything, including passwords, completely unprotected.",
        "attack": "Anyone between your office and the server can read the password and take full control.",
        "action": "Disable Telnet immediately and use SSH instead.",
    },
    25: {
        "name": "outgoing email (SMTP)", "public_ok": True, "severity": Severity.MEDIUM,
        "why": "This is how your business sends and receives email.",
        "attack": "If it is misconfigured, criminals can send scam emails that appear to come from your company.",
        "action": "Ask your provider to confirm the mail server does not relay mail for strangers, and that SPF, DKIM and DMARC are set up.",
    },
    53: {
        "name": "domain name lookup (DNS)", "public_ok": True, "severity": Severity.LOW,
        "why": "DNS is the phone book that points your domain name at your servers.",
        "attack": "A misconfigured DNS server can be abused to attack other companies, which can get your address blacklisted.",
        "action": "Ask your hosting provider to confirm the DNS server does not answer lookups for unrelated domains.",
    },
    80: {
        "name": "website traffic without encryption (HTTP)", "public_ok": True, "severity": Severity.MEDIUM,
        "why": "Anything typed into a page served this way, including passwords, travels unprotected.",
        "attack": "Someone on the same wifi as your customer can read or alter what is sent.",
        "action": "Install an HTTPS certificate and automatically redirect all visitors to the secure version of the site.",
    },
    110: {
        "name": "old email collection (POP3)", "public_ok": False, "severity": Severity.HIGH,
        "why": "This older way of collecting email can send passwords unprotected.",
        "attack": "An attacker who captures the password can read every email in the mailbox.",
        "action": "Switch staff to the encrypted version of email collection and close this door.",
    },
    135: {
        "name": "Windows internal service", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "This is an internal Windows service that should never be reachable from the internet.",
        "attack": "It is one of the first things attackers look for to break into Windows machines and spread ransomware.",
        "action": "Block this port at your firewall today. It should only be reachable inside your office network.",
    },
    139: {
        "name": "Windows file sharing (older)", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "Windows file sharing exposed to the internet is one of the most common ways ransomware gets in.",
        "attack": "Attackers scan the whole internet for this and use it to plant ransomware on shared drives.",
        "action": "Block this port at your firewall today.",
    },
    143: {
        "name": "email inbox access (IMAP)", "public_ok": True, "severity": Severity.MEDIUM,
        "why": "This is how staff mail programs read their inbox.",
        "attack": "If it is not encrypted, an attacker can capture mailbox passwords.",
        "action": "Confirm with your email provider that only the encrypted version is enabled.",
    },
    443: {
        "name": "secure website traffic (HTTPS)", "public_ok": True, "severity": Severity.LOW,
        "why": "This is the normal, encrypted way visitors reach your website.",
        "attack": "Nothing on its own, but any weakness in the website software behind it is reachable by everyone.",
        "action": "Keep the website software behind it up to date.",
    },
    445: {
        "name": "Windows file sharing (SMB)", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "Windows file sharing exposed to the internet is the single most common ransomware entry point for small businesses.",
        "attack": "Attackers scan for this constantly and use it to encrypt every file on your shared drives and demand payment.",
        "action": "Block this port at your firewall today. File sharing must never be reachable from the internet.",
    },
    1433: {
        "name": "Microsoft SQL database", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "Your database holds your customer and business records, and it is answering the public internet directly.",
        "attack": "Attackers guess the database password and copy your entire customer list in minutes.",
        "action": "Block database access at the firewall so only your own web server can reach it.",
    },
    3306: {
        "name": "MySQL database", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "Your database holds your customer and business records, and it is answering the public internet directly.",
        "attack": "Attackers guess the database password and copy your entire customer list in minutes.",
        "action": "Block database access at the firewall so only your own web server can reach it.",
    },
    3389: {
        "name": "Windows remote desktop", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "Remote desktop open to the internet is how a large share of ransomware attacks on small businesses begin.",
        "attack": "Bots guess staff passwords around the clock; one weak password gives an attacker your desktop.",
        "action": "Put remote desktop behind a VPN, or restrict it to your office IP address, and turn on two-step login.",
    },
    5432: {
        "name": "PostgreSQL database", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "Your database holds your customer and business records, and it is answering the public internet directly.",
        "attack": "Attackers guess the database password and copy your entire customer list in minutes.",
        "action": "Block database access at the firewall so only your own web server can reach it.",
    },
    5900: {
        "name": "remote screen sharing (VNC)", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "This lets someone see and control a computer screen from anywhere.",
        "attack": "Many of these are left with no password at all; attackers find them with a simple search and watch staff work.",
        "action": "Block this port at the firewall and use a VPN for remote support instead.",
    },
    6379: {
        "name": "Redis data store", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "This service often holds login sessions and ships with no password by default.",
        "attack": "Attackers connect without any password, read active logins, and can often take over the server.",
        "action": "Block this port at the firewall and set a password on the service.",
    },
    8080: {
        "name": "alternative website port", "public_ok": True, "severity": Severity.MEDIUM,
        "why": "Admin tools and test applications are very often left running on this port and forgotten.",
        "attack": "Attackers check this port first when looking for forgotten management pages.",
        "action": "Check what is running here. If it is a management tool, restrict it to your office IP address.",
    },
    8443: {
        "name": "alternative secure website port", "public_ok": True, "severity": Severity.LOW,
        "why": "Management interfaces are commonly published here.",
        "attack": "Attackers check this port for login pages to guess passwords against.",
        "action": "Confirm what is running here and restrict it if it is a management tool.",
    },
    9200: {
        "name": "Elasticsearch search database", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "This type of database usually has no password by default and often holds a full copy of your business data.",
        "attack": "Attackers download the entire contents with a single web request, then demand a ransom to delete their copy.",
        "action": "Block this port at the firewall immediately and turn on authentication.",
    },
    27017: {
        "name": "MongoDB database", "public_ok": False, "severity": Severity.CRITICAL,
        "why": "This database ships with no password by default and holds your application's records.",
        "attack": "Attackers connect with no password, copy your data, delete it, and leave a ransom note.",
        "action": "Block this port at the firewall immediately and set a database password.",
    },
}

#: Keywords found in vulnerability descriptions, translated into the
#: real-world consequence a business owner cares about.
IMPACT_KEYWORDS: list[tuple[tuple[str, ...], str, str]] = [
    (("remote code execution", "arbitrary code", "code execution", "rce"),
     "lets an attacker run their own programs on your server",
     "install ransomware, steal your files, or use your server to attack others"),
    (("sql injection", "sqli"),
     "lets an attacker ask your database questions it should refuse",
     "download your full customer list, including anything you store about them"),
    (("authentication bypass", "improper authentication", "auth bypass", "unauthenticated"),
     "lets an attacker skip the login screen entirely",
     "get in as an administrator without ever knowing a password"),
    (("privilege escalation", "elevation of privilege"),
     "lets a low-level user promote themselves to full administrator",
     "take complete control of the machine once they have any foothold"),
    (("directory traversal", "path traversal", "arbitrary file read", "file disclosure"),
     "lets an attacker read files on your server that should be private",
     "read configuration files containing your passwords and database keys"),
    (("cross-site scripting", "xss"),
     "lets an attacker put their own content into pages your customers see",
     "steal a logged-in customer's session or show them a fake payment form"),
    (("denial of service", "dos", "crash"),
     "lets an attacker knock the service offline",
     "take your website down during your busiest trading hours"),
    (("information disclosure", "sensitive information", "exposure of sensitive"),
     "leaks information about your systems that should stay private",
     "learn exactly how to plan a more serious attack"),
    (("buffer overflow", "out-of-bounds", "memory corruption", "use after free"),
     "lets an attacker confuse the software into doing something it was never meant to do",
     "take control of the server process, often completely"),
    (("cross-site request forgery", "csrf"),
     "lets an attacker trick a logged-in staff member into making changes without realising",
     "change your settings or create a new admin account using a staff member's own browser"),
    (("default password", "hardcoded", "default credential"),
     "ships with a password that is publicly known",
     "log straight in using a password anyone can look up online"),
]

#: Service/product name -> what that software actually does, in plain English.
SERVICE_ROLES: dict[str, str] = {
    "nginx":        "your website server",
    "apache":       "your website server",
    "httpd":        "your website server",
    "iis":          "your website server",
    "microsoft-iis": "your website server",
    "litespeed":    "your website server",
    "tomcat":       "your web application server",
    "node":         "your web application server",
    "openssh":      "the remote control service on your server",
    "ssh":          "the remote control service on your server",
    "mysql":        "your database",
    "mariadb":      "your database",
    "postgresql":   "your database",
    "postgres":     "your database",
    "mongodb":      "your database",
    "redis":        "your session and cache store",
    "elasticsearch": "your search database",
    "vsftpd":       "your file transfer server",
    "proftpd":      "your file transfer server",
    "pure-ftpd":    "your file transfer server",
    "postfix":      "your email server",
    "exim":         "your email server",
    "sendmail":     "your email server",
    "dovecot":      "your email inbox server",
    "exchange":     "your Microsoft email server",
    "bind":         "your DNS name server",
    "wordpress":    "your WordPress website",
    "drupal":       "your Drupal website",
    "joomla":       "your Joomla website",
    "php":          "the programming platform behind your website",
    "openssl":      "the encryption library your server uses",
    "cloudflare":   "your website protection service",
    "sucuri":       "your website protection service",
    "cloudproxy":   "your website protection service",
}


# ===========================================================================
# Translation helpers — technical node -> plain English
# ===========================================================================

def _attrs(graph, node_id: str) -> dict:
    """Safely fetch a node's attribute dict, or {} if it is missing."""
    try:
        return dict(graph.G.nodes[node_id])
    except Exception:
        return {}


def _meta(graph, node_id: str) -> dict:
    meta = _attrs(graph, node_id).get("meta")
    return meta if isinstance(meta, dict) else {}


def _node_type(graph, node_id: str) -> str:
    return _attrs(graph, node_id).get("node_type", "")


def _label(graph, node_id: str) -> str:
    return _attrs(graph, node_id).get("label") or node_id


def describe_subdomain(host: str) -> tuple[str, bool, str]:
    """
    Work out what a hostname most likely is, in plain English.

    Returns ``(friendly_role, should_be_public, extra_concern)``.
    Unknown prefixes fall back to a neutral description, and the function
    never raises.
    """
    host = (host or "").strip().lower().rstrip(".")
    first = host.split(".")[0] if host else ""

    if first in SUBDOMAIN_ROLES:
        return SUBDOMAIN_ROLES[first]

    # Fall back to a keyword search inside the label, e.g. "admin-old"
    for key, value in SUBDOMAIN_ROLES.items():
        if len(key) >= 3 and key in first:
            return value

    return (f"a website address you own ({host})", True, "")


def friendly_name(graph, node_id: str) -> str:
    """
    Convert any graph node ID into something a business owner recognises.

    Examples::

        "svc:nginx@192.124.249.6:80/tcp"  -> "your website server (nginx)"
        "192.124.249.6:3306/tcp"          -> "the MySQL database door on 192.124.249.6"
        "admin.yourdomain.com"            -> "your admin control panel (admin.yourdomain.com)"
        "CVE-2021-44228"                  -> "a known weakness in your software"

    This is the single place technical names are humanised. Phase 2's attack
    story engine and the PDF report both reuse it so the wording stays
    consistent everywhere the business owner looks.
    """
    if not node_id:
        return "an unknown asset"

    ntype = _node_type(graph, node_id)
    label = _label(graph, node_id)

    if ntype == "domain":
        return f"your main domain ({label})"

    if ntype == "subdomain":
        role, _public, _concern = describe_subdomain(label)
        if role.startswith("a website address you own"):
            return role
        return f"{role} ({label})"

    if ntype == "ip":
        return f"one of your servers ({label})"

    if ntype == "port":
        meta = _meta(graph, node_id)
        port = _safe_int(meta.get("port"))
        host = node_id.split(":")[0]
        profile = PORT_PROFILES.get(port)
        if profile:
            return f"the {profile['name']} door on {host}"
        return f"an open door (port {port or label}) on {host}"

    if ntype == "service":
        role = _service_role(label)
        version = _meta(graph, node_id).get("version", "")
        version_txt = f" version {version}" if version else ""
        return f"{role} ({label}{version_txt})"

    if ntype == "technology":
        role = _service_role(label)
        if role.startswith("software called"):
            return role
        return f"{role} ({label})"

    if ntype == "cve" or str(node_id).upper().startswith("CVE-"):
        return "a publicly known weakness in software you run"

    return str(label)


def _service_role(name: str) -> str:
    """Map a product/service name onto what it does, in plain English."""
    clean = (name or "").strip().lower()
    if not clean:
        return "a service on your server"

    for key, role in SERVICE_ROLES.items():
        if key in clean:
            return role
    return f"software called {name}"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def describe_vulnerability(description: str, cvss: float) -> tuple[str, str]:
    """
    Turn a raw CVE description into ``(what_it_does, what_attacker_gains)``
    in plain English, with no CVE ID and no jargon.

    Falls back to a generic-but-honest sentence when the description does not
    match anything we recognise, so a finding is never dropped just because we
    could not classify it.
    """
    text = (description or "").lower()

    for keywords, what_it_does, attacker_gain in IMPACT_KEYWORDS:
        if any(k in text for k in keywords):
            return what_it_does, attacker_gain

    if cvss >= 9.0:
        return ("has a serious flaw that security researchers rate as one of the worst kinds",
                "take control of the affected system")
    if cvss >= 7.0:
        return ("has a flaw that is known to be usable in real attacks",
                "get further into your systems than they should be able to")
    return ("has a known weakness that has been publicly documented",
            "combine it with other weaknesses to work their way in")


# ===========================================================================
# Graph reading helpers
# ===========================================================================

def _iter_nodes(graph) -> Iterable[tuple[str, dict]]:
    try:
        return list(graph.G.nodes(data=True))
    except Exception as exc:                      # pragma: no cover - defensive
        log.error("Could not read nodes from graph: %s", exc)
        return []


def _nodes_of_type(graph, node_type: str) -> list[str]:
    return [n for n, d in _iter_nodes(graph) if d.get("node_type") == node_type]


def _neighbours(graph, node_id: str) -> list[str]:
    """All directly connected nodes, ignoring edge direction.

    Edge direction in the graph is not consistent (a service points *at* its
    port, while an IP points *at* its ports), so for "what is attached to
    what" questions we deliberately treat the graph as undirected.
    """
    try:
        return list(set(graph.G.successors(node_id)) | set(graph.G.predecessors(node_id)))
    except Exception:
        return []


def _cves_for_asset(graph, asset_id: str) -> list[dict]:
    """
    Every CVE attached to a service/technology node, with its score and
    description, sorted worst-first.
    """
    results = []
    for neighbour in _neighbours(graph, asset_id):
        if _node_type(graph, neighbour) != "cve" and not str(neighbour).upper().startswith("CVE-"):
            continue
        attrs = _attrs(graph, neighbour)
        meta  = _meta(graph, neighbour)
        cvss  = _safe_float(meta.get("cvss"), _safe_float(attrs.get("risk_score")))
        results.append({
            "id":          neighbour,
            "cvss":        cvss,
            # cve_lookup.py replaces meta after add_cve(), which can drop the
            # description — fall back gracefully rather than showing nothing.
            "description": meta.get("description", "") or attrs.get("description", ""),
            "published":   meta.get("published", ""),
        })
    return sorted(results, key=lambda c: c["cvss"], reverse=True)


def _host_for_asset(graph, node_id: str) -> str:
    """
    Best-effort: which hostname or IP does this node live on?
    Used so findings can say *where* something is, not just *what* it is.
    """
    ntype = _node_type(graph, node_id)
    if ntype in ("domain", "subdomain", "ip"):
        return _label(graph, node_id)

    raw = str(node_id)
    if ntype == "service" and "@" in raw:
        raw = raw.split("@", 1)[1]
    if ntype in ("port", "service") and ":" in raw:
        candidate = raw.split(":")[0]
        if candidate:
            return candidate

    for neighbour in _neighbours(graph, node_id):
        if _node_type(graph, neighbour) in ("ip", "subdomain", "domain"):
            return _label(graph, neighbour)
    return ""


def _steps_from_internet(graph, node_id: str) -> Optional[int]:
    """
    How many hops from a public entry point (the domain) to this asset.

    Used for the "an attacker could reach your database in 2 steps from the
    internet" style of sentence. Treats the graph as undirected because edge
    direction in builder.py is a modelling convention, not a description of
    how an attacker actually moves. Returns ``None`` when there is no route.
    """
    entry_points = _nodes_of_type(graph, "domain") or _nodes_of_type(graph, "subdomain")
    if not entry_points:
        return None

    try:
        import networkx as nx
        undirected = graph.G.to_undirected(as_view=True)
        best = None
        for entry in entry_points:
            try:
                hops = nx.shortest_path_length(undirected, entry, node_id)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue
            best = hops if best is None else min(best, hops)
        return best
    except Exception as exc:                      # pragma: no cover - defensive
        log.debug("Could not measure distance to %s: %s", node_id, exc)
        return None


def _reach_sentence(graph, node_id: str) -> str:
    """A plain English clause about how far inside this asset sits."""
    steps = _steps_from_internet(graph, node_id)
    if steps is None or steps <= 0:
        return "It is reachable directly from the public internet."
    if steps == 1:
        return "It is one step away from anyone on the public internet."
    return f"An attacker could reach it in {steps} steps from the public internet."


# ===========================================================================
# Finding generators
# ===========================================================================

def _findings_from_vulnerabilities(graph) -> list[Finding]:
    """
    Known software weaknesses, grouped per affected asset.

    One finding per asset (not per CVE) — a business owner wants "your web
    server has 3 serious weaknesses", not thirty near-identical entries.
    """
    findings: list[Finding] = []

    # Services first: cve_lookup.py queries service *and* technology nodes with
    # the same keyword, so the same software often carries the same CVEs twice.
    # The service node is the more useful one to report (it knows the host and
    # port), so a technology node adding nothing new is skipped.
    reported_cves: set[str] = set()

    assets = _nodes_of_type(graph, "service") + _nodes_of_type(graph, "technology")
    for asset_id in assets:
        cves = _cves_for_asset(graph, asset_id)
        if not cves:
            continue

        cve_ids = {c["id"] for c in cves}
        if _node_type(graph, asset_id) == "technology" and cve_ids <= reported_cves:
            continue
        reported_cves |= cve_ids

        worst    = cves[0]
        severity = cvss_to_severity(worst["cvss"])
        asset    = friendly_name(graph, asset_id)
        host     = _host_for_asset(graph, asset_id)
        where    = f" on {host}" if host else ""
        count    = len(cves)
        plural   = "weakness" if count == 1 else "weaknesses"

        what_it_does, attacker_gain = describe_vulnerability(
            worst["description"], worst["cvss"]
        )

        version = _meta(graph, asset_id).get("version", "")
        if version:
            action = (
                f"Ask whoever manages your website to update {_label(graph, asset_id)} "
                f"(currently version {version}){where} to the latest version."
            )
        else:
            action = (
                f"Ask whoever manages your website to update the software running "
                f"{asset}{where} to the latest version."
            )

        findings.append(Finding(
            severity=severity,
            what_is_exposed=(
                f"{_capitalise(asset)}{where} is running software with {count} "
                f"publicly known security {plural}."
            ),
            why_it_matters=(
                f"The most serious of these {what_it_does}. "
                f"{_reach_sentence(graph, asset_id)}"
            ),
            how_attacker_uses_it=(
                f"Instructions for this are already published online, so an attacker "
                f"can follow a recipe to {attacker_gain}."
            ),
            recommended_action=action,
            asset=asset,
            node_id=asset_id,
            cvss=worst["cvss"],
            category="vulnerability",
            evidence=[
                f"{c['id']} (CVSS {c['cvss']:.1f})" for c in cves[:10]
            ] + [f"affected node: {asset_id}"],
        ))

    return findings


def _findings_from_open_ports(graph) -> list[Finding]:
    """Doors that are open to the whole internet and probably should not be."""
    findings: list[Finding] = []

    for port_id in _nodes_of_type(graph, "port"):
        attrs = _attrs(graph, port_id)
        if not attrs.get("exposed", True):
            continue

        meta    = _meta(graph, port_id)
        port    = _safe_int(meta.get("port"))
        profile = PORT_PROFILES.get(port)
        host    = _host_for_asset(graph, port_id) or "one of your servers"

        if profile is None:
            # Unknown port — still worth a low-severity note, since forgotten
            # services are exactly what attackers hunt for.
            findings.append(Finding(
                severity=Severity.LOW,
                what_is_exposed=(
                    f"An unusual service is reachable from the internet on {host} "
                    f"(port {port or attrs.get('label', '?')})."
                ),
                why_it_matters=(
                    "Services on unusual ports are often something that was set up "
                    "temporarily and then forgotten, which means nobody is updating it."
                ),
                how_attacker_uses_it=(
                    "Attackers scan for unusual services precisely because forgotten "
                    "software is rarely kept up to date."
                ),
                recommended_action=(
                    f"Ask your IT person what is running on port {port} on {host}. "
                    "If nobody needs it, close it at the firewall."
                ),
                asset=friendly_name(graph, port_id),
                node_id=port_id,
                category="exposure",
                evidence=[f"open port: {port_id}"],
            ))
            continue

        # Ports that are normally fine in public and carry no extra risk here
        # are not worth alarming a business owner about.
        if profile["public_ok"] and profile["severity"] == Severity.LOW:
            continue

        findings.append(Finding(
            severity=profile["severity"],
            what_is_exposed=(
                f"The {profile['name']} service on {host} is reachable by anyone "
                f"on the internet."
            ),
            why_it_matters=profile["why"],
            how_attacker_uses_it=profile["attack"],
            recommended_action=profile["action"],
            asset=friendly_name(graph, port_id),
            node_id=port_id,
            category="exposure",
            evidence=[f"open port: {port_id}"],
        ))

    return findings


def _findings_from_sensitive_hosts(graph) -> list[Finding]:
    """
    Addresses that exist publicly but describe something private:
    admin panels, staging copies, backups, internal tools.
    """
    findings: list[Finding] = []

    # Group by role first. A brute-force subdomain scan often turns up db.,
    # mysql. and database. all at once — the owner needs one clear item
    # ("5 database addresses are public"), not five copies of the same advice.
    groups: dict[str, dict[str, Any]] = {}

    for host_id in _nodes_of_type(graph, "subdomain"):
        attrs = _attrs(graph, host_id)
        if not attrs.get("exposed", True):
            continue

        label = _label(graph, host_id)
        role, should_be_public, concern = describe_subdomain(label)
        if should_be_public:
            continue

        group = groups.setdefault(role, {
            "role": role, "concern": concern, "hosts": [], "node_ids": [],
        })
        group["hosts"].append(label)
        group["node_ids"].append(host_id)

    for role, group in groups.items():
        hosts = sorted(group["hosts"])
        count = len(hosts)

        severity = Severity.HIGH
        if any(word in role for word in ("admin", "database", "backup", "hosting control")):
            severity = Severity.CRITICAL

        if count == 1:
            what = f"{_capitalise(role)} is published on the public internet at {hosts[0]}."
            action = (
                f"Restrict {hosts[0]} so it only answers requests from your office IP "
                f"address or through your VPN. If it is no longer used, take it offline entirely."
            )
        else:
            listed = ", ".join(hosts[:5]) + (f" and {count - 5} more" if count > 5 else "")
            what = (
                f"{count} addresses that look like {role} are published on the public "
                f"internet: {listed}."
            )
            action = (
                f"Ask your IT person which of these {count} addresses are still needed. "
                f"Take the unused ones offline, and restrict the rest to your office IP "
                f"address or your VPN."
            )

        findings.append(Finding(
            severity=severity,
            what_is_exposed=what,
            why_it_matters=(
                f"{group['concern']} Anyone in the world can find "
                f"{'these addresses' if count > 1 else 'this address'}, not just your staff."
            ).strip(),
            how_attacker_uses_it=(
                "Attackers list every address belonging to a company in seconds using "
                "free public tools, then try common passwords against the login page they find."
            ),
            recommended_action=action,
            asset=role,
            node_id=group["node_ids"][0],
            category="exposure",
            evidence=[f"public hostname: {h}" for h in hosts],
        ))

    return findings


def _findings_from_missing_https(graph) -> list[Finding]:
    """A website answering on plain HTTP with no HTTPS door alongside it."""
    findings: list[Finding] = []

    by_host: dict[str, set[int]] = {}
    for port_id in _nodes_of_type(graph, "port"):
        host = _host_for_asset(graph, port_id)
        port = _safe_int(_meta(graph, port_id).get("port"))
        if host and port:
            by_host.setdefault(host, set()).add(port)

    for host, ports in by_host.items():
        if 80 in ports and not ({443, 8443} & ports):
            findings.append(Finding(
                severity=Severity.HIGH,
                what_is_exposed=(
                    f"The website on {host} is served without encryption, and there is "
                    f"no secure version available."
                ),
                why_it_matters=(
                    "Everything visitors type into the site, including passwords and "
                    "contact details, travels in a form that can be read along the way."
                ),
                how_attacker_uses_it=(
                    "Someone sharing a wifi network with your customer can read what they "
                    "submit, or quietly change the page they see."
                ),
                recommended_action=(
                    f"Install a free HTTPS certificate on {host} and set the site to send "
                    f"every visitor to the secure address automatically."
                ),
                asset=f"the website on {host}",
                node_id=host,
                category="encryption",
                evidence=[f"{host} has port 80 open and no 443/8443"],
            ))

    return findings


def _findings_from_topology(graph) -> list[Finding]:
    """
    The graph-theory findings, stripped of all graph theory.

    A node with very high betweenness centrality is, in business terms, a
    single point of failure: lots of routes run through it.
    """
    findings: list[Finding] = []

    try:
        betweenness = graph.betweenness_centrality()
    except Exception as exc:                      # pragma: no cover - defensive
        log.debug("Could not compute topology findings: %s", exc)
        return findings

    if not betweenness:
        return findings

    ranked = sorted(betweenness.items(), key=lambda kv: kv[1], reverse=True)
    for node_id, score in ranked[:3]:
        # Only meaningful when the node really is a hub.
        if score < 0.15:
            continue
        if _node_type(graph, node_id) in ("cve", ""):
            continue

        asset = friendly_name(graph, node_id)
        findings.append(Finding(
            severity=Severity.MEDIUM,
            what_is_exposed=(
                f"{_capitalise(asset)} sits in the middle of your setup — most of your "
                f"other systems depend on it."
            ),
            why_it_matters=(
                "If this one system is taken over or goes down, an attacker gains a "
                "foothold that reaches most of the rest of your business."
            ),
            how_attacker_uses_it=(
                "Attackers deliberately look for the busiest system, because breaking "
                "that one saves them from breaking ten others."
            ),
            recommended_action=(
                f"Treat {asset} as your most important system: apply its updates first, "
                f"turn on two-step login for it, and make sure it is backed up separately."
            ),
            asset=asset,
            node_id=node_id,
            category="architecture",
            evidence=[f"betweenness centrality {score:.3f} for {node_id}"],
        ))

    return findings


def _capitalise(text: str) -> str:
    """Capitalise the first letter only, leaving the rest of the sentence alone."""
    text = str(text or "").strip()
    return text[0].upper() + text[1:] if text else text


# ===========================================================================
# Public API
# ===========================================================================

def generate_findings(graph, include_low: bool = True) -> list[Finding]:
    """
    Run every finding generator over the graph and return a clean, sorted,
    de-duplicated list of plain English findings.

    Each generator is run in isolation: if one of them fails on an unusual
    graph, the rest of the report is still produced.
    """
    generators = (
        ("vulnerabilities", _findings_from_vulnerabilities),
        ("open ports",      _findings_from_open_ports),
        ("sensitive hosts", _findings_from_sensitive_hosts),
        ("encryption",      _findings_from_missing_https),
        ("architecture",    _findings_from_topology),
    )

    findings: list[Finding] = []
    for name, generator in generators:
        try:
            findings.extend(generator(graph))
        except Exception as exc:
            log.error("Could not generate %s findings: %s", name, exc)

    # De-duplicate: the same asset and category should only be raised once.
    seen: set[tuple[str, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.node_id, finding.category)
        if key in seen:
            continue
        seen.add(key)
        if not include_low and finding.severity == Severity.LOW:
            continue
        unique.append(finding)

    unique.sort(key=lambda f: (Severity.sort_key(f.severity), -f.cvss, f.asset))
    return unique


def overall_risk_level(findings: Iterable[Finding]) -> str:
    """
    One overall answer to "am I safe?".

    A single critical issue makes the whole business critical — that is how a
    real attacker sees it, and it is what the owner needs to hear.
    """
    findings = list(findings)
    if not findings:
        return Severity.LOW
    return min((f.severity for f in findings), key=Severity.sort_key)


def headline(findings: Iterable[Finding], target: str = "") -> str:
    """The single sentence a business owner reads first."""
    findings = list(findings)
    counts   = severity_counts(findings)
    level    = overall_risk_level(findings)
    subject  = target if target else "your business"

    if not findings:
        return (
            f"Good news: we found nothing that needs your attention on {subject} "
            f"in this scan."
        )
    if level == Severity.CRITICAL:
        n = counts[Severity.CRITICAL]
        return (
            f"{n} urgent problem{'s' if n != 1 else ''} found on {subject} "
            f"could let a criminal in today. Please act on these first."
        )
    if level == Severity.HIGH:
        n = counts[Severity.HIGH]
        return (
            f"Nothing is on fire, but {n} serious issue{'s' if n != 1 else ''} on "
            f"{subject} should be fixed this week."
        )
    if level == Severity.MEDIUM:
        return (
            f"{_capitalise(subject)} is in reasonable shape. There are some things "
            f"worth tightening up, but nothing urgent."
        )
    return f"{_capitalise(subject)} looks healthy. Only minor tidy-up items were found."


def severity_counts(findings: Iterable[Finding]) -> dict[str, int]:
    """How many findings at each level (always includes all four keys)."""
    counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH:     0,
        Severity.MEDIUM:   0,
        Severity.LOW:      0,
    }
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


#: How much each severity level contributes to the 0-100 risk score.
RISK_WEIGHTS = {
    Severity.CRITICAL: 25.0,
    Severity.HIGH:     12.0,
    Severity.MEDIUM:    5.0,
    Severity.LOW:       1.0,
}


def overall_risk_score(findings: Iterable[Finding]) -> float:
    """
    A single 0-100 number summarising how exposed the business is.

    This exists so the monitoring layer can answer "did things get worse since
    yesterday?" with a percentage. It is deliberately simple and additive: one
    critical issue is worth roughly two high ones, and the score saturates at
    100 rather than growing without limit, because "very bad" and "even worse"
    call for the same response from a business owner.

    It is a trend indicator, not a scientific measurement — treat a change in
    the number as the signal, not the number itself.
    """
    total = sum(
        RISK_WEIGHTS.get(finding.severity, 0.0)
        for finding in findings
    )
    return round(min(total, 100.0), 1)


def risk_score_words(score: float) -> str:
    """Describe a 0-100 risk score the way a business owner would say it."""
    if score >= 70:
        return "very exposed"
    if score >= 40:
        return "more exposed than it should be"
    if score >= 15:
        return "reasonably protected, with a few gaps"
    return "in good shape"


def top_actions(findings: Iterable[Finding], limit: int = 3) -> list[str]:
    """
    The "if you only do three things this week" list.

    De-duplicated, because the same advice often comes out of several findings.
    """
    actions: list[str] = []
    for finding in findings:
        action = finding.recommended_action.strip()
        if action and action not in actions:
            actions.append(action)
        if len(actions) >= limit:
            break
    return actions


def asset_inventory(graph) -> dict[str, Any]:
    """A plain English count of everything the scan discovered."""
    counts: dict[str, int] = {}
    for _node, attrs in _iter_nodes(graph):
        node_type = attrs.get("node_type", "unknown")
        counts[node_type] = counts.get(node_type, 0) + 1

    friendly = {
        "domain":     "main domain",
        "subdomain":  "website addresses",
        "ip":         "servers",
        "port":       "open doors (ports)",
        "service":    "running services",
        "technology": "software products",
        "cve":        "known software weaknesses",
    }
    return {
        "raw":      counts,
        "friendly": {friendly.get(k, k): v for k, v in counts.items()},
        "total":    sum(counts.values()),
    }


def generate_report(graph, include_low: bool = True) -> dict:
    """
    Build the complete plain English report for a scanned graph.

    Returns a JSON-serialisable dict, so the same structure feeds the CLI,
    the Flask API, the PDF generator and the email alerts.
    """
    findings = generate_findings(graph, include_low=include_low)
    target   = getattr(graph, "target", "") or ""

    return {
        "target":          target,
        "generated_at":    datetime.now().isoformat(timespec="seconds"),
        "overall_risk":    overall_risk_level(findings),
        "risk_score":      overall_risk_score(findings),
        "headline":        headline(findings, target),
        "severity_counts": severity_counts(findings),
        "top_actions":     top_actions(findings, limit=3),
        "inventory":       asset_inventory(graph),
        "findings":        [f.to_dict() for f in findings],
    }


# ===========================================================================
# Text rendering (CLI output)
# ===========================================================================

def format_report_text(report: dict, width: int = 78) -> str:
    """
    Render a report dict as plain text for the terminal.

    Deliberately ASCII-only: this has to render correctly in the default
    Windows console, which cannot print box-drawing characters or emoji.
    """
    rule = "=" * width
    thin = "-" * width
    out: list[str] = []

    out.append(rule)
    out.append("  YOUR SECURITY REPORT".ljust(width - 1))
    if report.get("target"):
        out.append(f"  Website checked : {report['target']}")
    out.append(f"  Date            : {str(report.get('generated_at', ''))[:16].replace('T', ' ')}")
    out.append(rule)
    out.append("")
    out.append(_wrap(f"OVERALL RISK: {report.get('overall_risk', Severity.LOW)}",
                     width, "  ", first="  "))
    out.append(_wrap(report.get("headline", ""), width, "  ", first="  "))
    out.append("")

    counts = report.get("severity_counts", {})
    out.append("  " + "   ".join(
        f"{level}: {counts.get(level, 0)}"
        for level in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)
    ))
    out.append("")

    actions = report.get("top_actions") or []
    if actions:
        out.append(thin)
        out.append("  IF YOU ONLY DO THREE THINGS THIS WEEK")
        out.append(thin)
        for i, action in enumerate(actions, 1):
            out.append(_wrap(f"  {i}. {action}", width, "     "))
        out.append("")

    inventory = (report.get("inventory") or {}).get("friendly", {})
    if inventory:
        out.append(thin)
        out.append("  WHAT WE FOUND")
        out.append(thin)
        for name, count in inventory.items():
            out.append(f"  {count:>4}  {name}")
        out.append("")

    findings = report.get("findings") or []
    out.append(thin)
    out.append(f"  EVERYTHING WE FOUND ({len(findings)} item{'s' if len(findings) != 1 else ''})")
    out.append(thin)

    if not findings:
        out.append("  Nothing needs your attention right now.")
    for i, raw in enumerate(findings, 1):
        finding = Finding(**{k: v for k, v in raw.items() if k in Finding.__dataclass_fields__})
        out.append("")
        out.append(f"  [{i}] {'-' * (width - 8)}")
        out.append(finding.to_text(width=width))

    out.append("")
    out.append(rule)
    return "\n".join(out)


def print_report(graph, include_low: bool = True) -> dict:
    """Convenience: build a report, print it, and hand the dict back."""
    report = generate_report(graph, include_low=include_low)
    print(format_report_text(report))
    return report


# ===========================================================================
# CLI:  python -m reports.plain_english attack_surface.json
# ===========================================================================

if __name__ == "__main__":
    import argparse

    from graph.builder import AttackSurfaceGraph

    parser = argparse.ArgumentParser(
        description="Turn a SurfaceWatch scan into a plain English report."
    )
    parser.add_argument("scan_file", nargs="?", default="attack_surface.json",
                        help="Path to a saved scan JSON file")
    parser.add_argument("--json", action="store_true",
                        help="Print the report as JSON instead of text")
    parser.add_argument("--hide-low", action="store_true",
                        help="Hide LOW severity findings")
    args = parser.parse_args()

    try:
        loaded_graph = AttackSurfaceGraph.load(args.scan_file)
    except FileNotFoundError:
        raise SystemExit(f"Scan file not found: {args.scan_file}")
    except Exception as error:
        raise SystemExit(f"Could not read scan file '{args.scan_file}': {error}")

    result = generate_report(loaded_graph, include_low=not args.hide_low)

    if args.json:
        import json
        print(json.dumps(result, indent=2))
    else:
        print(format_report_text(result))
