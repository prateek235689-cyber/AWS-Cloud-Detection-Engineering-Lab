"""Detect potentially risky IAM policy changes in CloudTrail-style events."""

import json
from pathlib import Path


def detect_iam_policy_changes(events):
    """Generate findings for selected IAM policy modification events."""

    suspicious_events = {
        "PutUserPolicy",
        "PutRolePolicy",
        "PutGroupPolicy",
        "AttachUserPolicy",
        "AttachRolePolicy",
        "AttachGroupPolicy",
        "CreatePolicyVersion",
        "SetDefaultPolicyVersion",
    }

    findings = []

    for event in events:
        if (
            event.get("eventSource") == "iam.amazonaws.com"
            and event.get("eventName") in suspicious_events
        ):
            findings.append(
                {
                    "rule_id": "AWS-IAM-002",
                    "severity": "MEDIUM",
                    "title": "IAM policy modification detected",
                    "event_name": event.get("eventName"),
                    "actor": event.get("userIdentity", {}).get(
                        "userName", "Unknown"
                    ),
                    "source_ip": event.get("sourceIPAddress", "Unknown"),
                    "target": event.get("requestParameters", {}),
                    "event_time": event.get("eventTime", "Unknown"),
                }
            )

    return findings


def main():
    project_root = Path(__file__).resolve().parent.parent
    event_file = (
        project_root
        / "sample_events"
        / "suspicious_iam_policy_change.json"
    )

    with event_file.open("r", encoding="utf-8") as file:
        events = json.load(file)

    findings = detect_iam_policy_changes(events)

    print(f"Events loaded: {len(events)}")
    print(f"Findings generated: {len(findings)}")

    for finding in findings:
        print(json.dumps(finding, indent=2))


if __name__ == "__main__":
    main()
