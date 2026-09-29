"""
report.py

Turns the enriched findings (analyzer.py output + cloudtrail_check.py
usage evidence) into a human-readable report — printed to console and
also written out as a Markdown file.
"""

from datetime import datetime, timezone
from analyzer import summarize

SEVERITY_ICON = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
}


def print_console_report(findings):
    summary = summarize(findings)

    print("\n" + "=" * 70)
    print("IAM PRIVILEGE ESCALATION AUDIT — SUMMARY")
    print("=" * 70)
    print(f"Total findings:        {summary['total_findings']}")
    print(f"Identities at risk:    {summary['identities_at_risk']}")
    print(f"  CRITICAL: {summary['by_severity'].get('CRITICAL', 0)}")
    print(f"  HIGH:     {summary['by_severity'].get('HIGH', 0)}")
    print(f"  MEDIUM:   {summary['by_severity'].get('MEDIUM', 0)}")
    print("=" * 70)

    if not findings:
        print("\nNo privilege escalation paths detected. ✅")
        return

    for f in findings:
        icon = SEVERITY_ICON.get(f["severity"], "⚪")
        print(f"\n{icon} [{f['severity']}] {f['identity_type'].upper()}: {f['identity_name']}")
        print(f"   Technique: {f['rule_name']}")
        print(f"   {f['description']}")
        print(f"   Required permissions matched: {', '.join(f['matched_actions'])}")

        usage = f.get("usage_evidence", [])
        if usage:
            print(f"   ⚠️  ACTIVE USAGE DETECTED ({len(usage)} event(s) in lookback window):")
            for e in usage[:3]:
                print(f"       - {e['event_name']} at {e['event_time']} by {e['actor']}")
        else:
            print(f"   Usage: no recent CloudTrail evidence of this permission being exercised.")


def write_markdown_report(findings, path="iam_privesc_report.md"):
    summary = summarize(findings)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = []
    lines.append(f"# IAM Privilege Escalation Audit Report")
    lines.append(f"_Generated: {now}_\n")
    lines.append("## Summary\n")
    lines.append(f"- **Total findings:** {summary['total_findings']}")
    lines.append(f"- **Identities at risk:** {summary['identities_at_risk']}")
    lines.append(f"- **Critical:** {summary['by_severity'].get('CRITICAL', 0)}")
    lines.append(f"- **High:** {summary['by_severity'].get('HIGH', 0)}")
    lines.append(f"- **Medium:** {summary['by_severity'].get('MEDIUM', 0)}\n")

    if not findings:
        lines.append("No privilege escalation paths detected. ✅\n")
    else:
        lines.append("## Findings\n")
        lines.append("| Severity | Identity | Type | Technique | Matched Permissions | Recent Usage |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            usage_str = f"{len(f.get('usage_evidence', []))} event(s)" if f.get("usage_evidence") else "None observed"
            lines.append(
                f"| {f['severity']} | {f['identity_name']} | {f['identity_type']} | "
                f"{f['rule_name']} | `{', '.join(f['matched_actions'])}` | {usage_str} |"
            )

        lines.append("\n## Details\n")
        for f in findings:
            lines.append(f"### {f['identity_name']} — {f['rule_name']} ({f['severity']})")
            lines.append(f"- **Identity ARN:** `{f['identity_arn']}`")
            lines.append(f"- **Description:** {f['description']}")
            lines.append(f"- **Matched permissions:** `{', '.join(f['matched_actions'])}`")
            usage = f.get("usage_evidence", [])
            if usage:
                lines.append(f"- **Usage evidence:**")
                for e in usage:
                    lines.append(f"  - `{e['event_name']}` at {e['event_time']} by `{e['actor']}`")
            else:
                lines.append("- **Usage evidence:** none found in lookback window")
            lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines))

    print(f"\n[*] Markdown report written to: {path}")
