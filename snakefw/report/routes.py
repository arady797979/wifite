#!/usr/bin/env python3
"""Snake report API — HTML and JSON deliverables."""
from flask import Blueprint, jsonify, render_template, request

from snakefw.report.builder import build_report

report_bp = Blueprint("report", __name__)


def _wants_secrets() -> bool:
    return request.args.get("include_secrets") in {"1", "true", "yes"}


@report_bp.route("/api/report")
def report_json():
    include = _wants_secrets()
    return jsonify({"ok": True, "report": build_report(include_secrets=include)})


@report_bp.route("/api/report/html")
def report_html():
    include = _wants_secrets()
    report = build_report(include_secrets=include)
    return render_template("report.html", report=report)
