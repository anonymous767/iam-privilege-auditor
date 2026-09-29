"""
cloudtrail_check.py

For each privesc finding, checks CloudTrail event history to see whether
the risky action(s) have actually been USED by that identity recently.

This turns the report from "here's what's theoretically possible" into
"here's what's theoretically possible AND here's what's actually been
happening" — which is what makes it useful for triage. A CRITICAL finding
that's never been touched is a config-hardening task; a CRITICAL finding
with real recent usage is an incident to investigate right now.

Required IAM permission to RUN this part:
    cloudtrail:LookupEvents

Note: CloudTrail's event name is usually the action name without the
service prefix, e.g. IAM action "iam:CreateAccessKey" -> CloudTrail
EventName "CreateAccessKey". We strip the prefix to search.
"""

import boto3
from datetime import datetime, timedelta, timezone
from botocore.exceptions import ClientError


class CloudTrailChecker:
    def __init__(self, session=None, lookback_days=90):
        self.session = session or boto3.Session()
        self.client = self.session.client("cloudtrail")
        self.lookback_days = lookback_days

    def _event_name_from_action(self, action):
        # "iam:CreateAccessKey" -> "CreateAccessKey"
        return action.split(":", 1)[-1]

    def check_usage(self, finding):
        """
        Given a single finding dict (from analyzer.py), check CloudTrail
        for any events where the matched action(s) were called BY this
        identity (as the actor) in the lookback window.

        Returns a list of usage event summaries:
        [{"event_name": ..., "event_time": ..., "actor": ...}, ...]
        Empty list means no evidence of use found in the lookback window.
        """
        usage_events = []
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(days=self.lookback_days)

        for action in finding["matched_actions"]:
            event_name = self._event_name_from_action(action)
            try:
                response = self.client.lookup_events(
                    LookupAttributes=[
                        {"AttributeKey": "EventName", "AttributeValue": event_name}
                    ],
                    StartTime=start_time,
                    EndTime=end_time,
                    MaxResults=20,
                )
            except ClientError as e:
                print(f"  [!] CloudTrail lookup failed for {event_name}: {e}")
                continue

            for event in response.get("Events", []):
                # Filter down to events actually performed by our identity
                # of interest, not just anyone in the account.
                username = event.get("Username", "")
                if finding["identity_name"] in username or finding["identity_name"] in str(event.get("Resources", "")):
                    usage_events.append({
                        "event_name": event_name,
                        "event_time": event["EventTime"].isoformat(),
                        "actor": username,
                    })

        return usage_events

    def enrich_findings(self, findings):
        """
        Takes the full findings list from analyzer.py, adds a
        'usage_evidence' key to each finding, and returns the enriched list.
        """
        print(f"[*] Cross-referencing {len(findings)} findings against CloudTrail "
              f"(last {self.lookback_days} days)...")

        for finding in findings:
            usage = self.check_usage(finding)
            finding["usage_evidence"] = usage
            if usage:
                print(f"    -> ACTIVE USAGE found for {finding['identity_name']} "
                      f"/ {finding['rule_name']}")

        return findings
