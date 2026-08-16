import os
import json
import logging
import threading
import traceback
from datetime import datetime

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, current_app
from flask_login import login_required, current_user

from app import db
from app.models import Scan
from graph.builder import AttackSurfaceGraph
from scanners.subdomain_enum import enumerate_subdomains
from scanners.port_scanner import scan_ports

log = logging.getLogger(__name__)

dashboard = Blueprint("dashboard", __name__, url_prefix="/dashboard")

SCANS_DIR = os.path.join(os.getcwd(), "scans")
os.makedirs(SCANS_DIR, exist_ok=True)


@dashboard.route("/")
@login_required
def index():
    user_scans = Scan.query.filter_by(user_id=current_user.id) \
                            .order_by(Scan.created_at.desc()).all()
    return render_template("dashboard/index.html", scans=user_scans)


@dashboard.route("/scan", methods=["POST"])
@login_required
def start_scan():
    raw_target = request.form.get("target", "").strip()
    if not raw_target:
        flash("Please enter a domain to scan.", "danger")
        return redirect(url_for("dashboard.index"))

    # Clean up target string (remove http://, https://, file:///, paths, spaces)
    target = raw_target.lower()
    for prefix in ("http://", "https://", "file:///"):
        if target.startswith(prefix):
            target = target[len(prefix):]
    target = target.split("/")[0].split(":")[0].strip()

    if not target:
        flash("Invalid domain target provided.", "danger")
        return redirect(url_for("dashboard.index"))

    scan = Scan(user_id=current_user.id, target=target, status="running")
    db.session.add(scan)
    db.session.commit()

    # Grab the REAL app instance (not a new one) to reuse in the thread
    real_app = current_app._get_current_object()
    user_id  = current_user.id

    thread = threading.Thread(target=_run_scan, args=(real_app, scan.id, target, user_id))
    thread.daemon = True
    thread.start()

    flash(f"Scan started for {target}. Refresh in a minute to see results.", "info")
    return redirect(url_for("dashboard.index"))


def _run_scan(app, scan_id: int, target: str, user_id: int):
    """
    Runs in a background thread - performs the actual scan.
    Uses the SAME app instance passed in (not a new one) to avoid
    conflicting SQLAlchemy/db instances.
    """
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            log.error("Scan %d not found in database.", scan_id)
            return

        try:
            log.info("Starting background scan %d for target '%s'", scan_id, target)
            graph = AttackSurfaceGraph(target=target)
            graph.add_domain(target)

            try:
                enumerate_subdomains(graph, target)
            except Exception as sub_err:
                log.warning("Subdomain enumeration error for %s: %s", target, sub_err)

            try:
                scan_ports(graph, target)
            except Exception as port_err:
                log.warning("Port scan error for %s: %s", target, port_err)

            result_path = os.path.join(SCANS_DIR, f"scan_{scan_id}.json")
            graph.save(result_path)

            summary = graph.summary()

            top = []
            try:
                top = graph.top_risk_nodes(top_n=1)
            except Exception as risk_err:
                log.warning("Failed to compute top risk node for %s: %s", target, risk_err)

            scan.status      = "done"
            scan.finished_at = datetime.utcnow()
            scan.result_file = result_path
            scan.node_count  = summary["total_nodes"]
            scan.edge_count  = summary["total_edges"]
            scan.risk_score  = top[0]["combined"] if top else 0.0

            from app.models import User
            user = User.query.get(user_id)
            if user:
                user.scan_count = (user.scan_count or 0) + 1

            db.session.commit()
            log.info("Scan %d completed successfully: %d nodes, %d edges, risk: %.3f",
                     scan_id, summary["total_nodes"], summary["total_edges"], scan.risk_score)

        except Exception as e:
            # Log the FULL error traceback
            log.error("Scan %d FAILED for target '%s': %s", scan_id, target, e)
            log.error(traceback.format_exc())
            print("="*60)
            print(f"SCAN {scan_id} FAILED — target: {target}")
            print(traceback.format_exc())
            print("="*60)

            scan.status = "failed"
            db.session.commit()


@dashboard.route("/results/<int:scan_id>")
@login_required
def view_results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.owner.id != current_user.id:
        flash("You don't have access to that scan.", "danger")
        return redirect(url_for("dashboard.index"))

    graph_data = {"nodes": [], "edges": []}
    report = None
    stories = []
    if scan.result_file and os.path.exists(scan.result_file):
        with open(scan.result_file) as f:
            graph_data = json.load(f)

        try:
            from graph.builder import AttackSurfaceGraph
            from reports.plain_english import generate_report
            from reports.attack_story import generate_story_report

            g = AttackSurfaceGraph.load(scan.result_file)
            report = generate_report(g)
            stories = generate_story_report(g).get("stories", [])
        except Exception as err:
            log.warning("Failed generating report for scan %d: %s", scan_id, err)

    return render_template("dashboard/results.html", scan=scan, graph_data=graph_data, report=report, stories=stories)


@dashboard.route("/api/scan/<int:scan_id>/status")
@login_required
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    return jsonify({"status": scan.status, "node_count": scan.node_count,
                     "edge_count": scan.edge_count, "risk_score": scan.risk_score})


@dashboard.route("/results/<int:scan_id>/pdf")
@login_required
def download_pdf(scan_id):
    from flask import send_file
    scan = Scan.query.get_or_404(scan_id)
    if scan.owner.id != current_user.id:
        flash("You don't have access to that scan.", "danger")
        return redirect(url_for("dashboard.index"))

    if not scan.result_file or not os.path.exists(scan.result_file):
        flash("Scan result file not found.", "danger")
        return redirect(url_for("dashboard.view_results", scan_id=scan_id))

    try:
        from graph.builder import AttackSurfaceGraph
        from reports.pdf_generator import generate_pdf

        g = AttackSurfaceGraph.load(scan.result_file)
        pdf_filename = f"surfacewatch-report-{scan.target}-{scan.created_at.strftime('%Y-%m-%d')}.pdf"
        pdf_path = os.path.join(SCANS_DIR, f"report_{scan_id}.pdf")

        generate_pdf(g, pdf_path)

        return send_file(
            pdf_path,
            as_attachment=True,
            download_name=pdf_filename,
            mimetype="application/pdf"
        )
    except Exception as e:
        log.error("Failed to generate PDF for scan %d: %s\n%s", scan_id, e, traceback.format_exc())
        flash("Could not generate PDF report.", "danger")
        return redirect(url_for("dashboard.view_results", scan_id=scan_id))


@dashboard.route("/scan/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.owner.id != current_user.id:
        flash("You don't have permission to delete this scan.", "danger")
        return redirect(url_for("dashboard.index"))

    if scan.result_file and os.path.exists(scan.result_file):
        try:
            os.remove(scan.result_file)
        except Exception as e:
            log.warning("Could not remove scan file %s: %s", scan.result_file, e)

    pdf_path = os.path.join(SCANS_DIR, f"report_{scan_id}.pdf")
    if os.path.exists(pdf_path):
        try:
            os.remove(pdf_path)
        except Exception as e:
            log.warning("Could not remove PDF report file %s: %s", pdf_path, e)

    db.session.delete(scan)
    db.session.commit()
    flash(f"Scan for {scan.target} deleted successfully.", "success")
    return redirect(url_for("dashboard.index"))