"""
analyzer.py

Takes the raw collected data (which actions each identity is allowed to
perform) and matches it against the known privesc rules to find actual
escalation paths.

An identity "triggers" a rule if it holds ALL of that rule's required
actions simultaneously.
"""

from privesc_rules import PRIVESC_RULES


def analyze(collected_data):
    """
    collected_data: output of IAMCollector.collect()

    Returns a list of findings:
    [
        {
            "identity_arn": "...",
            "identity_name": "...",
            "identity_type": "user" | "role",
            "rule_name": "...",
            "description": "...",
            "severity": "CRITICAL" | "HIGH" | "MEDIUM",
            "matched_actions": [...],
        },
        ...
    ]
    Sorted with CRITICAL findings first.
    """
    findings = []

    for arn, info in collected_data.items():
        allowed = info["allowed_actions"]

        for rule in PRIVESC_RULES:
            required = set(rule["required"])
            if required.issubset(allowed):
                findings.append({
                    "identity_arn": arn,
                    "identity_name": info["name"],
                    "identity_type": info["type"],
                    "rule_name": rule["name"],
                    "description": rule["description"],
                    "severity": rule["severity"],
                    "matched_actions": sorted(required),
                })

    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    findings.sort(key=lambda f: severity_order.get(f["severity"], 99))

    return findings


def summarize(findings):
    """Quick counts by severity, useful for a report header."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    identities_at_risk = set()

    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        identities_at_risk.add(f["identity_arn"])

    return {
        "total_findings": len(findings),
        "by_severity": counts,
        "identities_at_risk": len(identities_at_risk),
    }
