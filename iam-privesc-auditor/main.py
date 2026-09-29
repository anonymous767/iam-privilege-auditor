"""
main.py

IAM Privilege Escalation Detector & Auditor — entry point.

Usage:
    python main.py                       # uses default AWS credentials/profile
    python main.py --profile myprofile   # uses a named AWS CLI profile
    python main.py --skip-cloudtrail     # skip usage cross-referencing (faster,
                                          # needs fewer permissions)

Running against LocalStack instead of real AWS:
    python main.py --endpoint-url http://localhost:4566 --local-eval --skip-cloudtrail
"""

import argparse
import boto3

from iam_collector import IAMCollector
from analyzer import analyze
from cloudtrail_check import CloudTrailChecker
from report import print_console_report, write_markdown_report


def main():
    parser = argparse.ArgumentParser(description="AWS IAM Privilege Escalation Auditor")
    parser.add_argument("--profile", help="AWS CLI profile name to use", default=None)
    parser.add_argument("--region", help="AWS region", default="us-east-1")
    parser.add_argument("--endpoint-url", default=None,
                         help="Override the AWS endpoint (e.g. http://localhost:4566 "
                              "to target LocalStack instead of real AWS)")
    parser.add_argument("--local-eval", action="store_true",
                         help="Skip AWS's SimulatePrincipalPolicy API and evaluate "
                              "policies ourselves instead (needed for LocalStack's "
                              "free tier, which may not include the simulator)")
    parser.add_argument("--skip-cloudtrail", action="store_true",
                         help="Skip CloudTrail usage cross-referencing")
    parser.add_argument("--lookback-days", type=int, default=90,
                         help="How many days of CloudTrail history to check (default: 90)")
    parser.add_argument("--output", default="iam_privesc_report.md",
                         help="Path for the Markdown report")
    args = parser.parse_args()

    if args.endpoint_url:
        # LocalStack doesn't validate credentials, but boto3 still requires
        # something present to construct a client.
        session = boto3.Session(
            aws_access_key_id="test",
            aws_secret_access_key="test",
            region_name=args.region,
        )
    else:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)

    print("[*] Step 1/3: Collecting IAM identities and resolving their permissions...")
    collector = IAMCollector(session=session, use_local_eval=args.local_eval)
    if args.endpoint_url:
        collector.iam = session.client("iam", endpoint_url=args.endpoint_url)
    collected_data = collector.collect()

    print("\n[*] Step 2/3: Analyzing collected permissions against known privesc techniques...")
    findings = analyze(collected_data)
    print(f"    Found {len(findings)} potential privilege escalation path(s).")

    if not args.skip_cloudtrail and findings:
        print("\n[*] Step 3/3: Cross-referencing findings against CloudTrail history...")
        checker = CloudTrailChecker(session=session, lookback_days=args.lookback_days)
        if args.endpoint_url:
            checker.client = session.client("cloudtrail", endpoint_url=args.endpoint_url)
        findings = checker.enrich_findings(findings)
    else:
        print("\n[*] Step 3/3: Skipped (no findings or --skip-cloudtrail set).")
        for f in findings:
            f["usage_evidence"] = []

    print_console_report(findings)
    write_markdown_report(findings, path=args.output)


if __name__ == "__main__":
    main()
