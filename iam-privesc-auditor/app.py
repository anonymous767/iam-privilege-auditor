"""
app.py

Web dashboard for the IAM Privilege Escalation Auditor.

Run:
    python3 app.py

Then open http://localhost:5000 in a browser.

This is a thin UI layer over the exact same pipeline main.py uses
(iam_collector -> analyzer -> cloudtrail_check -> report) — no logic is
duplicated. It just triggers a scan from a web form and renders the
findings instead of printing to console.
"""

import os
from flask import Flask, render_template, request, send_file, redirect, url_for
import boto3

from iam_collector import IAMCollector
from analyzer import analyze, summarize
from cloudtrail_check import CloudTrailChecker
from report import write_markdown_report

app = Flask(__name__)

# In-memory cache of the last scan's results. Fine for a single-user local
# tool like this — no need for a database or session store.
LAST_RESULTS = {
    "findings": None,
    "summary": None,
    "config": None,
    "error": None,
}

REPORT_PATH = "iam_privesc_report.md"


def run_scan(endpoint_url, local_eval, skip_cloudtrail, profile, region, lookback_days):
    if endpoint_url:
        session = boto3.Session(
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name=region,
        )
    else:
        session = boto3.Session(profile_name=profile or None, region_name=region)

    collector = IAMCollector(session=session, use_local_eval=local_eval)
    if endpoint_url:
        collector.iam = session.client("iam", endpoint_url=endpoint_url)

    collected_data = collector.collect()
    findings = analyze(collected_data)

    if not skip_cloudtrail and findings:
        checker = CloudTrailChecker(session=session, lookback_days=lookback_days)
        if endpoint_url:
            checker.client = session.client("cloudtrail", endpoint_url=endpoint_url)
        findings = checker.enrich_findings(findings)
    else:
        for f in findings:
            f["usage_evidence"] = []

    write_markdown_report(findings, path=REPORT_PATH)
    return findings


@app.route("/", methods=["GET"])
def index():
    return render_template(
        "index.html",
        findings=LAST_RESULTS["findings"],
        summary=LAST_RESULTS["summary"],
        config=LAST_RESULTS["config"],
        error=LAST_RESULTS["error"],
        report_exists=os.path.exists(REPORT_PATH),
    )


@app.route("/scan", methods=["POST"])
def scan():
    endpoint_url = request.form.get("endpoint_url", "").strip() or None
    local_eval = request.form.get("local_eval") == "on"
    skip_cloudtrail = request.form.get("skip_cloudtrail") == "on"
    profile = request.form.get("profile", "").strip()
    region = request.form.get("region", "us-east-1").strip() or "us-east-1"
    lookback_days = int(request.form.get("lookback_days", 90) or 90)

    LAST_RESULTS["config"] = {
        "endpoint_url": endpoint_url,
        "local_eval": local_eval,
        "skip_cloudtrail": skip_cloudtrail,
        "profile": profile,
        "region": region,
        "lookback_days": lookback_days,
    }

    try:
        findings = run_scan(endpoint_url, local_eval, skip_cloudtrail, profile, region, lookback_days)
        LAST_RESULTS["findings"] = findings
        LAST_RESULTS["summary"] = summarize(findings)
        LAST_RESULTS["error"] = None
    except Exception as e:
        LAST_RESULTS["findings"] = None
        LAST_RESULTS["summary"] = None
        LAST_RESULTS["error"] = str(e)

    return redirect(url_for("index"))


@app.route("/download-report")
def download_report():
    if not os.path.exists(REPORT_PATH):
        return redirect(url_for("index"))
    return send_file(REPORT_PATH, as_attachment=True)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
