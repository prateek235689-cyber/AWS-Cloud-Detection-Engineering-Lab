"""Simple CloudTrail detection engine for the lab."""

import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


THRESHOLD = 3
WINDOW_MINUTES = 5


def parse_time(value):
    """Parse a CloudTrail timestamp into a timezone-aware datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def detect_failed_console_logins(events):
    """Detect repeated failed console logins by source IP."""
    failed_logins = defaultdict(list)

    for event in events:
        if (
            event.get("eventSource") == "signin.amazonaws.com"
            and event.get("eventName") == "ConsoleLogin"
            and event.get("responseElements", {}).get("ConsoleLogin") == "Failure"
        ):
            source_ip = event.get("sourceIPAddress", "Unknown")
            failed_logins[source_ip].append(event)

    findings = []

    for source_ip, attempts in failed_logins.items():
        attempts.sort(key=lambda event: parse_time(event["eventTime"]))

        for start_index, first_event in enumerate(attempts):
            start_time = parse_time(first_event["eventTime"])
            window_end = start_time + timedelta(minutes=WINDOW_MINUTES)

            matching = [
                event
                for event in attempts[start_index:]
                if start_time <= parse_time(event["eventTime"]) <= window_end
            ]

            if len(matching) >= THRESHOLD:
                findings.append(
                    {
                        "rule_id": "AWS-LOGIN-001",
                        "severity": "MEDIUM",
                        "title": "Repeated failed AWS console sign-ins",
                        "source_ip": source_ip,
                        "attempt_count": len(matching),
                        "window_minutes": WINDOW_MINUTES,
                        "usernames": sorted(
                            {
                                event.get("userIdentity", {}).get(
                                    "userName", "Unknown"
                                )
                                for event in matching
                            }
                        ),
                    }
                )
                break

    return findings


def main():
    project_root = Path(__file__).resolve().parent.parent
    event_file = project_root / "sample_events" / "failed_console_logins.json"

    with event_file.open("r", encoding="utf-8") as file:
        events = json.load(file)

    findings = detect_failed_console_logins(events)

    print(f"Events loaded: {len(events)}")
    print(f"Findings generated: {len(findings)}")

    for finding in findings:
        print(json.dumps(finding, indent=2))


if __name__ == "__main__":
    main()
