# SurfaceWatch — Attack Surface Monitor for SMBs

**Find out what a criminal can see of your business — explained in plain English, not security jargon.**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Docker](https://img.shields.io/badge/docker-ready-2496ed.svg)](https://www.docker.com/)
[![Cost](https://img.shields.io/badge/cost-%240%2Fmonth-brightgreen.svg)](#does-it-cost-anything)

Most small businesses cannot afford a penetration test, and cannot hire a
security team. They are told to "reduce their attack surface" without being
told what that means. SurfaceWatch scans everything your business has exposed to
the internet, then tells you — in ordinary English — what is wrong, why it
matters to *your* business, and exactly what to do about it.

> **CRITICAL:** Your admin control panel is published on the public internet at
> `admin.yourdomain.com`.
> **Why it matters:** It controls your whole website. Anyone in the world can
> find this address, not just your staff.
> **What to do:** Restrict `admin.yourdomain.com` so it only answers requests
> from your office IP address or through your VPN.

No CVE numbers. No CVSS vectors. No graph theory. Just what is wrong and what to do.

---

## Demo

<!-- Replace with a real recording: asciinema, or a GIF of `surfacewatch scan` -->
![SurfaceWatch demo](docs/demo.gif)

*Demo GIF placeholder — record with `surfacewatch scan --target yourdomain.com`.*

---

## Features

- ✅ **Plain English findings** — every issue in five fields: what is exposed, why it matters, how an attacker uses it, what to do
- ✅ **Attack path storytelling** — numbered narratives showing exactly how someone would break in, step by step
- ✅ **Continuous monitoring** — automatic rescans every 24 hours, so you learn about changes the day they happen
- ✅ **Plain English change reports** — *"2 new addresses appeared since yesterday: dev2.yourdomain.com (WARNING: no HTTPS)"*
- ✅ **Email alerts that stay quiet** — only for critical findings, new subdomains, a sharp risk rise, or an expiring certificate
- ✅ **Professional PDF reports** — six sections, colour coded, suitable for showing your IT person, your insurer or your board
- ✅ **HTML and JSON reports** — one self-contained file, or structured data for your own tooling
- ✅ **Subdomain discovery** — DNS brute force, no API key needed
- ✅ **Port and service scanning** — via Nmap, with version detection
- ✅ **Known weakness lookup** — live from the NIST National Vulnerability Database
- ✅ **Technology detection** — spots WordPress, PHP, nginx and 30+ others, and flags out-of-date versions
- ✅ **Website screenshots** — see the forgotten staging site with your own eyes
- ✅ **Passive Shodan lookup** — optional, free tier, never touches your servers
- ✅ **Interactive graph** — D3.js visualisation of your whole attack surface
- ✅ **Web dashboard** — Flask app with accounts and a community area
- ✅ **Runs entirely on your own machine** — your scan data never leaves it

---

## Quick start (Docker, 3 commands)

```bash
git clone https://github.com/yourusername/surfacewatch.git && cd surfacewatch
cp .env.example .env
docker compose up -d
```

Open **http://localhost:5000**.

Scan a domain straight away:

```bash
docker compose exec surfacewatch python -m cli.surfacewatch scan --target yourdomain.com --output report.pdf
```

The image includes Nmap and Chromium. For a much smaller image without
screenshots, build with `--build-arg INCLUDE_BROWSER=false`.

---

## Full installation

### Requirements

- Python 3.11 or newer
- [Nmap](https://nmap.org/download.html) — the port scanner SurfaceWatch drives
- Google Chrome or Chromium — *only* for screenshots; everything else works without it

### Install

```bash
git clone https://github.com/yourusername/surfacewatch.git
cd surfacewatch

python -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate

pip install -r requirements.txt
```

### Configure

Copy `.env.example` to `.env`. **Every setting is optional** — SurfaceWatch runs
with an empty file, just with fewer features.

```ini
# Makes weakness lookups about 10x faster. Free.
# https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=

# Adds passive discovery via Shodan. Free tier. Skipped if blank.
# https://account.shodan.io/
SHODAN_API_KEY=

# Email alerts. Leave blank to disable them entirely.
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=you@example.com
SMTP_PASSWORD=your-app-password        # Gmail: an App Password, not your login
SMTP_FROM=SurfaceWatch <you@example.com>
ALERT_TO=owner@example.com
SMTP_USE_TLS=true

# Domains monitored automatically on start.
SURFACEWATCH_TARGETS=yourdomain.com
```

> **Never commit `.env`.** It is already in `.gitignore`.

### Run

```bash
python run.py                                        # web dashboard on :5000
python -m cli.surfacewatch scan --target yourdomain.com  # one-off scan
```

---

## CLI usage

```bash
python -m cli.surfacewatch --help
```

### Scan a domain

```bash
surfacewatch scan --target acme.com
surfacewatch scan --target acme.com --output report.pdf
surfacewatch scan --target acme.com --skip-cve --save-scan today.json
surfacewatch scan --target acme.com --screenshots --output report.pdf
```

| Option | What it does |
|---|---|
| `--target`, `-t` | Domain to scan **(required)** |
| `--output`, `-o` | Write a report here — `.pdf`, `.html` or `.json` |
| `--ports` | Which ports to check |
| `--skip-cve` | Skip the weakness lookup (much faster) |
| `--screenshots` | Photograph each website (needs Chrome) |
| `--save-scan` | Also save the raw scan JSON |
| `--verbose`, `-v` | Show detailed scanner output |

### Monitor continuously

```bash
surfacewatch monitor --target acme.com --interval 24h
surfacewatch monitor --target acme.com --target acme.co.uk --interval 12h
surfacewatch monitor --target acme.com --once          # one scan, then exit
```

Intervals accept `24h`, `30m`, `2d`, or a bare number meaning hours. Scans are
saved to `scans/YYYY-MM-DD_HH-MM_domain.json`, and each run is automatically
compared with the previous one.

### Produce a report from a saved scan

```bash
surfacewatch report --scan-file today.json --format pdf
surfacewatch report --scan-file today.json --format html --output report.html
surfacewatch report --scan-file today.json --format json
surfacewatch report --scan-file today.json --show      # print findings here too
```

### Compare two scans

```bash
surfacewatch diff --scan1 monday.json --scan2 friday.json
surfacewatch diff --scan-dir scans --domain acme.com   # the two most recent
```

```
1 new address, 1 new open door on acme.com since the last check.

  CRITICAL  The Windows remote desktop door on 203.0.113.10 has been
            opened to the internet since the last check.
  HIGH      staging.acme.com is new since the last check.
            (this looks like a staging copy of your site)
```

---

## Reports

| Format | Best for |
|---|---|
| **PDF** | Showing your IT person, insurer, or board. Six sections, colour coded. |
| **HTML** | Sharing by email or link. One self-contained file, works offline, dark mode aware. |
| **JSON** | Feeding your own tools. Full findings plus attack paths. |

The PDF contains:

1. **Executive summary** — overall risk, exposure meter, the three things to fix first
2. **Attack surface** — what you have exposed, ranked by risk
3. **Top vulnerabilities** — every critical and serious problem in plain English
4. **Attack paths** — how someone would actually break in, step by step
5. **Full inventory** — everything discovered, for whoever maintains your systems
6. **Screenshots** — what your websites look like (when captured)

---

## Python API

```python
from graph.builder import AttackSurfaceGraph
from reports.plain_english import generate_report, format_report_text
from reports.attack_story import generate_stories
from reports.pdf_generator import generate_pdf
from monitor.diff_engine import diff_latest_scans, format_diff_text

graph  = AttackSurfaceGraph.load("attack_surface.json")

report = generate_report(graph)
print(report["overall_risk"], report["risk_score"])
print(format_report_text(report))

for story in generate_stories(graph, top_n=3):
    print(story.to_text())

generate_pdf(graph, "report.pdf")

changes = diff_latest_scans("scans", "acme.com")
if changes and changes.has_changes:
    print(format_diff_text(changes))
```

### Monitoring inside your own Flask app

```python
from monitor.scheduler import start_monitoring

start_monitoring(app, ["acme.com"])     # runs in the background, never blocks
```

---

## REST API

The Flask app exposes the graph for the D3.js frontend:

| Method | Endpoint | Returns |
|---|---|---|
| `GET` | `/api/graph` | Full attack surface graph — nodes and edges |
| `GET` | `/api/summary` | Node and edge counts by type |
| `GET` | `/api/risk` | Ranked riskiest assets |

```bash
curl http://localhost:5000/api/graph
```

---

## How it works

```
Domain
  ├─ subdomain_enum.py   DNS brute force              → subdomain nodes
  ├─ port_scanner.py     Nmap -sV                     → port + service nodes
  ├─ tech_detect.py      headers, HTML, cookies, paths → technology nodes
  ├─ shodan_scanner.py   passive lookup (optional)    → ports, services, weaknesses
  ├─ screenshot.py       headless Chrome              → images on host nodes
  └─ cve_lookup.py       NIST NVD API                 → weakness nodes
                    ↓
        graph/builder.py  (NetworkX directed graph)
                    ↓
   ┌────────────────┼─────────────────┬──────────────────┐
   ↓                ↓                 ↓                  ↓
plain_english   attack_story    diff_engine        pdf/html report
  findings       narratives    what changed         the deliverable
                    ↓
              monitor/alerts.py → email, only when it matters
```

Every asset is a node; every relationship is an edge. That makes questions like
*"how many steps is my database from the public internet?"* a graph query
rather than guesswork — and it is what lets SurfaceWatch explain a real route in,
rather than just listing problems.

---

## Does it cost anything?

**No.** SurfaceWatch is free to run, permanently:

- No subscription, no account, no hosted service
- No paid APIs — the NVD is free, and Shodan is optional with a free tier
- No cloud costs — it runs on your laptop, your office machine, or any server you already have
- Every dependency is open source

The only thing it can cost you is a little bandwidth.

---

## Privacy

Your scan results never leave your machine. There is no telemetry, no phone
home, and no analytics. Reports are written to your disk; emails go through
*your* SMTP server. The optional Shodan lookup queries a public database about
your own IP addresses — it sends nothing about you.

---

## Legal and ethical use

**Only scan systems you own or have written permission to test.** Port scanning
someone else's infrastructure is illegal in many countries, including under the
Computer Misuse Act (UK) and the Computer Fraud and Abuse Act (US).

SurfaceWatch is built for a business owner checking their *own* attack surface.
Use it that way.

---

## Contributing

Contributions are very welcome — especially from people who work with small
businesses and know how they actually talk about this stuff.

1. Fork the repository and create a branch: `git checkout -b my-improvement`
2. Make your change, keeping the house style:
   - Every module has a docstring explaining what it does and why
   - **All user-facing text is plain English** — no CVE IDs, no CVSS, no jargon
   - Every module handles its own errors; one failure never kills a scan
   - API keys come from `.env`, never from the code
3. Test against a domain you own
4. Commit (`git commit -m 'Add X'`), push, and open a pull request

### Good first issues

- More subdomain roles in `SUBDOMAIN_ROLES` (`reports/plain_english.py`)
- More port profiles in `PORT_PROFILES` — plain English for ports we do not cover
- More technology signatures in `scanners/tech_detect.py`
- Translations — the plain English layer is deliberately isolated for this
- A real demo GIF for this README

### Project layout

```
surfacewatch/
├── graph/       the attack surface graph and its algorithms
├── scanners/    subdomain, port, CVE, technology, Shodan, screenshots
├── reports/     plain English, attack stories, PDF, HTML
├── monitor/     scheduler, diff engine, email alerts
├── cli/         the surfacewatch command line tool
├── api/         Flask REST API
├── app/         Flask web dashboard
├── frontend/    D3.js graph visualisation
└── scans/       scan history (used to work out what changed)
```

---

## Troubleshooting

**"Nmap error" or no ports found**
Install Nmap and make sure it is on your PATH. On Windows, run your terminal as
Administrator for faster scan types.

**CVE lookup is very slow**
That is the NVD's public rate limit — about one request every 7 seconds. A free
`NVD_API_KEY` makes it roughly 10x faster.

**"Screenshots skipped"**
Chrome or Chromium is not installed. Everything else still works. Check with:
`python -m scanners.screenshot --check`

**No alert emails**
Set `SMTP_HOST` and `ALERT_TO` in `.env`. With Gmail you need an
[App Password](https://support.google.com/accounts/answer/185833), not your
normal password. Preview an email without sending:
`python -m monitor.alerts --domain yourdomain.com --preview preview.html`

**"Nothing to compare"**
SurfaceWatch needs two scans of the same domain before it can tell you what
changed. Run `surfacewatch monitor` and check back tomorrow.

---

## License

MIT — see [LICENSE](LICENSE).

Free to use, modify, sell and redistribute. If it helps you protect a small
business, that is exactly what it is for.
