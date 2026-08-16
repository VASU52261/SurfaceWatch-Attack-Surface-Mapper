"""
monitor/alerts.py
-----------------
Sends the business owner an email when something needs their attention.

An alert is only worth sending if it would make someone act. SurfaceWatch emails
on four triggers and nothing else:

    1. A CRITICAL finding is present
    2. New addresses (subdomains) appeared since the last check
    3. The overall exposure score rose by more than 20%
    4. An HTTPS certificate expires within 30 days

The email itself is written for a person who does not work in IT: no CVE
identifiers, no CVSS scores, no jargon. It says what happened, why it matters,
and exactly what to do.

Configuration lives in ``.env`` — never in the code::

    SMTP_HOST=smtp.gmail.com
    SMTP_PORT=587
    SMTP_USER=you@example.com
    SMTP_PASSWORD=your-app-password
    SMTP_FROM=SurfaceWatch <you@example.com>
    ALERT_TO=owner@example.com,manager@example.com
    SMTP_USE_TLS=true

If SMTP is not configured, alerting is skipped with a log line rather than
failing the scan — monitoring must never break because email is misconfigured.
Use ``dry_run=True`` (or ``send_scan_alert(..., dry_run=True)``) to render the
email and inspect it without sending anything.
"""

from __future__ import annotations

import html
import logging
import os
import smtplib
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Any, Optional

from dotenv import load_dotenv

from reports.plain_english import Severity, risk_score_words

load_dotenv()

log = logging.getLogger(__name__)

#: Warn when a certificate has fewer days left than this.
CERT_EXPIRY_WARNING_DAYS = 30

#: Risk score rise, in percent, that justifies an email on its own.
RISK_INCREASE_ALERT_PCT = 20.0


# ===========================================================================
# Configuration
# ===========================================================================

@dataclass
class SMTPConfig:
    """SMTP settings, read from the environment. Never hard-code these."""

    host: str = ""
    port: int = 587
    user: str = ""
    password: str = field(default="", repr=False)   # keep out of logs and tracebacks
    sender: str = ""
    recipients: list[str] = field(default_factory=list)
    use_tls: bool = True

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.recipients)

    def describe(self) -> str:
        """Safe-to-log description. Deliberately never includes the password."""
        if not self.is_configured:
            return "SMTP not configured"
        return (f"{self.user or 'anonymous'}@{self.host}:{self.port} "
                f"-> {len(self.recipients)} recipient(s)")


def load_smtp_config() -> SMTPConfig:
    """Build an :class:`SMTPConfig` from environment variables."""
    raw_recipients = os.getenv("ALERT_TO", "")
    recipients = [r.strip() for r in raw_recipients.replace(";", ",").split(",") if r.strip()]

    try:
        port = int(os.getenv("SMTP_PORT", "587"))
    except ValueError:
        log.warning("SMTP_PORT is not a number - falling back to 587.")
        port = 587

    user = os.getenv("SMTP_USER", "")

    return SMTPConfig(
        host=os.getenv("SMTP_HOST", "").strip(),
        port=port,
        user=user,
        password=os.getenv("SMTP_PASSWORD", ""),
        sender=os.getenv("SMTP_FROM", "").strip() or user,
        recipients=recipients,
        use_tls=os.getenv("SMTP_USE_TLS", "true").strip().lower() in ("1", "true", "yes", "on"),
    )


# ===========================================================================
# HTTPS certificate expiry
# ===========================================================================

def check_certificate_expiry(host: str, port: int = 443,
                             timeout: float = 10.0) -> Optional[dict]:
    """
    Look up how many days are left on a site's HTTPS certificate.

    Returns ``{"host", "days_left", "expires", "issuer"}`` or ``None`` when the
    certificate cannot be read — a site with no HTTPS at all is a separate
    finding (Phase 1 reports it), not an error here.

    Uses only the standard library, so it adds no dependency.
    """
    if not host:
        return None

    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as secure:
                cert = secure.getpeercert()
    except (socket.timeout, socket.gaierror, ConnectionError, OSError) as exc:
        log.info("Could not read the certificate for %s: %s", host, exc)
        return None
    except ssl.SSLError as exc:
        log.info("HTTPS problem on %s: %s", host, exc)
        return None

    if not cert:
        return None

    not_after = cert.get("notAfter")
    if not not_after:
        return None

    try:
        expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
    except ValueError:
        log.info("Unexpected certificate date format for %s: %s", host, not_after)
        return None

    days_left = (expires - datetime.now(timezone.utc)).days

    issuer = ""
    for part in cert.get("issuer", ()):
        for key, value in part:
            if key == "organizationName":
                issuer = value

    return {
        "host":      host,
        "days_left": days_left,
        "expires":   expires.strftime("%d %B %Y"),
        "issuer":    issuer,
    }


# ===========================================================================
# Deciding whether to send anything
# ===========================================================================

@dataclass
class AlertReason:
    """One reason an email is being sent, phrased for the business owner."""

    trigger: str          # critical_finding | new_subdomains | risk_increase | cert_expiry
    severity: str
    headline: str
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "trigger":  self.trigger,
            "severity": self.severity,
            "headline": self.headline,
            "detail":   self.detail,
        }


def decide_alerts(report: Optional[dict] = None,
                  diff: Any = None,
                  cert: Optional[dict] = None) -> list[AlertReason]:
    """
    Work out whether anything justifies an email, and why.

    Args:
        report : a report dict from ``reports.plain_english.generate_report()``
        diff   : a ``DiffResult`` from ``monitor.diff_engine``
        cert   : the result of :func:`check_certificate_expiry`

    Returns the list of reasons. An empty list means stay quiet — which is the
    right outcome most days, and the reason this tool does not become noise
    that people learn to ignore.
    """
    reasons: list[AlertReason] = []

    # 1. Any critical finding
    if report:
        critical = [f for f in report.get("findings", [])
                    if f.get("severity") == Severity.CRITICAL]
        if critical:
            first = critical[0]
            reasons.append(AlertReason(
                trigger="critical_finding",
                severity=Severity.CRITICAL,
                headline=(
                    f"{len(critical)} urgent security problem"
                    f"{'s' if len(critical) != 1 else ''} need"
                    f"{'' if len(critical) != 1 else 's'} your attention today"
                ),
                detail=first.get("what_is_exposed", ""),
            ))

    if diff is not None:
        # 2. New addresses appeared
        try:
            new_subdomains = diff.of_kind("new_subdomain")
        except Exception:
            new_subdomains = []
        if new_subdomains:
            reasons.append(AlertReason(
                trigger="new_subdomains",
                severity=Severity.HIGH,
                headline=(
                    f"{len(new_subdomains)} new web address"
                    f"{'es' if len(new_subdomains) != 1 else ''} appeared on your business"
                ),
                detail=(
                    "If you did not set these up yourself, find out who did. New "
                    "addresses are one of the clearest early signs of trouble."
                ),
            ))

        # 3. Exposure rose sharply
        try:
            risk_jumped = diff.risk_change_pct > RISK_INCREASE_ALERT_PCT
        except Exception:
            risk_jumped = False
        if risk_jumped:
            sharp = diff.risk_change_pct >= 200
            reasons.append(AlertReason(
                trigger="risk_increase",
                severity=Severity.HIGH,
                headline=(
                    "Your exposure rose sharply since the last check"
                    if sharp else
                    f"Your exposure rose by {diff.risk_change_pct:.0f}% since the "
                    f"last check"
                ),
                detail=(
                    f"The score moved from {diff.old_risk_score:.0f} to "
                    f"{diff.new_risk_score:.0f} out of 100."
                ),
            ))

    # 4. Certificate about to expire
    if cert and cert.get("days_left") is not None:
        days = cert["days_left"]
        if days < 0:
            reasons.append(AlertReason(
                trigger="cert_expiry",
                severity=Severity.CRITICAL,
                headline=f"The security certificate for {cert['host']} has expired",
                detail=(
                    "Visitors are now seeing a browser warning telling them your site "
                    "is not safe. Renew it today."
                ),
            ))
        elif days <= CERT_EXPIRY_WARNING_DAYS:
            reasons.append(AlertReason(
                trigger="cert_expiry",
                severity=Severity.HIGH if days <= 7 else Severity.MEDIUM,
                headline=(
                    f"The security certificate for {cert['host']} expires in "
                    f"{days} day{'s' if days != 1 else ''}"
                ),
                detail=(
                    f"It runs out on {cert['expires']}. When it does, visitors will "
                    f"see a warning saying your site is not safe, and many will leave."
                ),
            ))

    reasons.sort(key=lambda r: Severity.sort_key(r.severity))
    return reasons


# ===========================================================================
# Email rendering
# ===========================================================================

def _esc(text: Any) -> str:
    """Escape anything going into the HTML email."""
    return html.escape(str(text or ""))


def build_subject(domain: str, reasons: list[AlertReason]) -> str:
    """A subject line that says what happened, readable on a phone screen."""
    if not reasons:
        return f"SurfaceWatch: nothing to report for {domain}"

    worst = reasons[0]
    prefix = "URGENT" if worst.severity == Severity.CRITICAL else "Heads up"
    return f"[SurfaceWatch] {prefix}: {worst.headline} ({domain})"


def build_html_email(domain: str,
                     reasons: list[AlertReason],
                     report: Optional[dict] = None,
                     diff: Any = None) -> str:
    """
    Build the HTML email body.

    Written as a table-based layout with inline styles, because that is what
    email clients such as Outlook and Gmail actually render reliably — modern
    CSS layout is stripped by many of them.
    """
    risk_score = float((report or {}).get("risk_score", 0) or 0)
    risk_level = (report or {}).get("overall_risk", Severity.LOW)
    accent     = Severity.COLORS.get(
        reasons[0].severity if reasons else risk_level, "#27ae60"
    )

    # --- reasons ---------------------------------------------------------
    reason_blocks = []
    for reason in reasons:
        colour = Severity.COLORS.get(reason.severity, "#7f8c8d")
        reason_blocks.append(f"""
          <tr><td style="padding:0 0 16px 0;">
            <table width="100%" cellpadding="0" cellspacing="0"
                   style="border-left:4px solid {colour};background:#fbfbfc;">
              <tr><td style="padding:14px 18px;">
                <div style="font:600 16px/1.4 Arial,Helvetica,sans-serif;color:#1f2933;">
                  {_esc(reason.headline)}
                </div>
                <div style="font:400 14px/1.6 Arial,Helvetica,sans-serif;color:#52606d;padding-top:6px;">
                  {_esc(reason.detail)}
                </div>
              </td></tr>
            </table>
          </td></tr>""")

    # --- what to do ------------------------------------------------------
    actions = (report or {}).get("top_actions", []) or []
    action_items = "".join(
        f"""<tr><td style="padding:0 0 10px 0;font:400 14px/1.6 Arial,Helvetica,sans-serif;color:#1f2933;">
              <span style="display:inline-block;width:22px;height:22px;border-radius:11px;
                           background:{accent};color:#ffffff;text-align:center;
                           font:700 13px/22px Arial,Helvetica,sans-serif;">{i}</span>
              &nbsp;{_esc(action)}
            </td></tr>"""
        for i, action in enumerate(actions[:3], 1)
    )
    actions_section = f"""
      <tr><td style="padding:8px 0 4px 0;">
        <div style="font:700 13px/1.4 Arial,Helvetica,sans-serif;color:#1f2933;
                    letter-spacing:.08em;text-transform:uppercase;padding-bottom:12px;">
          What to do next
        </div>
        <table width="100%" cellpadding="0" cellspacing="0">{action_items}</table>
      </td></tr>""" if action_items else ""

    # --- what changed ----------------------------------------------------
    changes_section = ""
    try:
        bad_changes = diff.bad_news[:6] if diff is not None else []
    except Exception:
        bad_changes = []
    if bad_changes:
        rows = "".join(
            f"""<tr><td style="padding:0 0 8px 0;font:400 14px/1.6 Arial,Helvetica,sans-serif;color:#52606d;">
                  &bull; {_esc(c.plain)}
                  {f'<span style="color:#c0392b;"> ({_esc(c.warning)})</span>' if c.warning else ''}
                </td></tr>"""
            for c in bad_changes
        )
        changes_section = f"""
      <tr><td style="padding:20px 0 4px 0;">
        <div style="font:700 13px/1.4 Arial,Helvetica,sans-serif;color:#1f2933;
                    letter-spacing:.08em;text-transform:uppercase;padding-bottom:12px;">
          What changed since last time
        </div>
        <table width="100%" cellpadding="0" cellspacing="0">{rows}</table>
      </td></tr>"""

    checked_on = datetime.now().strftime("%d %B %Y at %H:%M")

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#eef1f5;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#eef1f5;padding:24px 12px;">
 <tr><td align="center">
  <table width="600" cellpadding="0" cellspacing="0"
         style="max-width:600px;background:#ffffff;border-radius:10px;overflow:hidden;
                box-shadow:0 1px 3px rgba(16,24,40,.08);">

    <!-- header -->
    <tr><td style="background:{accent};padding:22px 28px;">
      <div style="font:700 20px/1.3 Arial,Helvetica,sans-serif;color:#ffffff;">
        SurfaceWatch Security Alert
      </div>
      <div style="font:400 14px/1.5 Arial,Helvetica,sans-serif;color:rgba(255,255,255,.9);padding-top:4px;">
        {_esc(domain)} &middot; checked {_esc(checked_on)}
      </div>
    </td></tr>

    <!-- body -->
    <tr><td style="padding:26px 28px 8px 28px;">
      <div style="font:400 15px/1.6 Arial,Helvetica,sans-serif;color:#1f2933;padding-bottom:20px;">
        We checked your website and found something you should know about.
      </div>
      <table width="100%" cellpadding="0" cellspacing="0">
        {''.join(reason_blocks)}
      </table>
    </td></tr>

    <!-- score -->
    <tr><td style="padding:4px 28px 0 28px;">
      <table width="100%" cellpadding="0" cellspacing="0"
             style="background:#f6f8fa;border-radius:8px;">
        <tr>
          <td style="padding:16px 18px;font:400 14px/1.5 Arial,Helvetica,sans-serif;color:#52606d;">
            Overall your business is <strong style="color:#1f2933;">{_esc(risk_score_words(risk_score))}</strong>.
          </td>
          <td align="right" style="padding:16px 18px;font:700 22px/1 Arial,Helvetica,sans-serif;color:{accent};">
            {risk_score:.0f}<span style="font:400 13px/1 Arial,Helvetica,sans-serif;color:#7b8794;">/100</span>
          </td>
        </tr>
      </table>
    </td></tr>

    <!-- actions + changes -->
    <tr><td style="padding:22px 28px 8px 28px;">
      <table width="100%" cellpadding="0" cellspacing="0">
        {actions_section}
        {changes_section}
      </table>
    </td></tr>

    <!-- footer -->
    <tr><td style="padding:22px 28px 26px 28px;border-top:1px solid #e4e7eb;">
      <div style="font:400 12px/1.6 Arial,Helvetica,sans-serif;color:#7b8794;">
        You are receiving this because SurfaceWatch is monitoring {_esc(domain)}.
        If any of this is unclear, forward this email to whoever looks after your
        website - it is written so they can act on it straight away.
      </div>
    </td></tr>

  </table>
 </td></tr>
</table>
</body>
</html>"""


def build_text_email(domain: str,
                     reasons: list[AlertReason],
                     report: Optional[dict] = None,
                     diff: Any = None) -> str:
    """
    Plain text version of the same email.

    Always sent alongside the HTML part, so the alert is still readable in
    text-only clients and does not look like spam.
    """
    lines = [
        "SURFACEWATCH SECURITY ALERT",
        f"{domain} - checked {datetime.now().strftime('%d %B %Y at %H:%M')}",
        "",
        "We checked your website and found something you should know about.",
        "",
    ]

    for reason in reasons:
        lines.append(f"[{reason.severity}] {reason.headline}")
        if reason.detail:
            lines.append(f"    {reason.detail}")
        lines.append("")

    if report:
        score = float(report.get("risk_score", 0) or 0)
        lines.append(f"Overall your business is {risk_score_words(score)} "
                     f"({score:.0f} out of 100).")
        lines.append("")

        actions = report.get("top_actions") or []
        if actions:
            lines.append("WHAT TO DO NEXT")
            for i, action in enumerate(actions[:3], 1):
                lines.append(f"  {i}. {action}")
            lines.append("")

    try:
        bad = diff.bad_news[:6] if diff is not None else []
    except Exception:
        bad = []
    if bad:
        lines.append("WHAT CHANGED SINCE LAST TIME")
        for change in bad:
            suffix = f" ({change.warning})" if change.warning else ""
            lines.append(f"  - {change.plain}{suffix}")
        lines.append("")

    lines.append("If any of this is unclear, forward this email to whoever looks "
                 "after your website.")
    return "\n".join(lines)


# ===========================================================================
# Sending
# ===========================================================================

def send_email(subject: str,
               html_body: str,
               text_body: str,
               config: Optional[SMTPConfig] = None,
               dry_run: bool = False) -> bool:
    """
    Send one alert email. Returns True when it was accepted by the server.

    Never raises: a mail server outage must not bring down monitoring. Every
    failure path is logged, and the password is never written to the log.
    """
    config = config or load_smtp_config()

    if not config.is_configured:
        log.warning(
            "Email alert not sent - SMTP is not configured. Set SMTP_HOST and "
            "ALERT_TO in your .env file to receive alerts."
        )
        return False

    message = EmailMessage()
    message["Subject"] = subject
    message["From"]    = config.sender or config.user
    message["To"]      = ", ".join(config.recipients)
    message.set_content(text_body)
    message.add_alternative(html_body, subtype="html")

    if dry_run:
        log.info("DRY RUN - not sending. Would email %s: %s",
                 config.describe(), subject)
        return True

    try:
        if config.port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(config.host, config.port, timeout=30,
                                  context=context) as server:
                if config.user:
                    server.login(config.user, config.password)
                server.send_message(message)
        else:
            with smtplib.SMTP(config.host, config.port, timeout=30) as server:
                server.ehlo()
                if config.use_tls:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                if config.user:
                    server.login(config.user, config.password)
                server.send_message(message)

    except smtplib.SMTPAuthenticationError:
        log.error(
            "Email alert failed: the mail server rejected the username or password. "
            "If you use Gmail, you need an app password, not your normal password."
        )
        return False
    except (smtplib.SMTPException, socket.error, OSError) as exc:
        log.error("Email alert failed: %s", exc)
        return False

    log.info("Alert email sent to %d recipient(s): %s",
             len(config.recipients), subject)
    return True


def send_scan_alert(domain: str,
                    report: Optional[dict] = None,
                    diff: Any = None,
                    check_cert: bool = True,
                    config: Optional[SMTPConfig] = None,
                    dry_run: bool = False) -> dict:
    """
    The one function the scheduler calls after every scan.

    Decides whether anything is worth an email, builds it, and sends it.
    Returns a small summary dict so the caller can log what happened::

        {"sent": True, "reasons": [...], "subject": "...", "certificate": {...}}

    Staying silent when nothing is wrong is a feature, not a failure.
    """
    outcome: dict[str, Any] = {
        "sent": False, "reasons": [], "subject": "", "certificate": None,
    }

    try:
        cert = check_certificate_expiry(domain) if check_cert else None
        outcome["certificate"] = cert

        reasons = decide_alerts(report=report, diff=diff, cert=cert)
        outcome["reasons"] = [r.to_dict() for r in reasons]

        if not reasons:
            log.info("Nothing worth alerting on for %s - staying quiet.", domain)
            return outcome

        subject = build_subject(domain, reasons)
        outcome["subject"] = subject

        outcome["sent"] = send_email(
            subject=subject,
            html_body=build_html_email(domain, reasons, report, diff),
            text_body=build_text_email(domain, reasons, report, diff),
            config=config,
            dry_run=dry_run,
        )

    except Exception as exc:                      # pragma: no cover - defensive
        log.error("Alerting failed for %s: %s", domain, exc)

    return outcome


# ===========================================================================
# CLI:  python -m monitor.alerts --domain example.com --preview alert.html
# ===========================================================================

if __name__ == "__main__":
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")

    parser = argparse.ArgumentParser(
        description="Preview or send a SurfaceWatch alert email."
    )
    parser.add_argument("--domain", required=True, help="Domain the alert is about")
    parser.add_argument("--scan-file", default="",
                        help="Scan JSON to build the report from")
    parser.add_argument("--preview", default="",
                        help="Write the HTML email to this file instead of sending")
    parser.add_argument("--send", action="store_true",
                        help="Actually send the email (otherwise it is a dry run)")
    parser.add_argument("--check-cert", action="store_true",
                        help="Also check the HTTPS certificate expiry date")
    args = parser.parse_args()

    scan_report = None
    if args.scan_file:
        from graph.builder import AttackSurfaceGraph
        from reports.plain_english import generate_report
        loaded = AttackSurfaceGraph.load(args.scan_file)
        scan_report = generate_report(loaded)

    certificate = check_certificate_expiry(args.domain) if args.check_cert else None
    if certificate:
        print(f"Certificate for {certificate['host']} expires in "
              f"{certificate['days_left']} days ({certificate['expires']})")

    alert_reasons = decide_alerts(report=scan_report, cert=certificate)
    if not alert_reasons:
        print("Nothing would trigger an alert right now.")
        raise SystemExit(0)

    print(f"Subject: {build_subject(args.domain, alert_reasons)}")
    for r in alert_reasons:
        print(f"  [{r.severity}] {r.headline}")

    if args.preview:
        with open(args.preview, "w", encoding="utf-8") as fh:
            fh.write(build_html_email(args.domain, alert_reasons, scan_report))
        print(f"\nHTML preview written to {args.preview}")

    if args.send:
        send_scan_alert(args.domain, report=scan_report, check_cert=args.check_cert)
    else:
        print("\n(Dry run - pass --send to actually email this.)")
