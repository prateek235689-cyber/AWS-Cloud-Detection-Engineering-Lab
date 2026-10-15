# AWS Cloud Detection Engineering Lab

A hands-on cybersecurity project focused on developing and testing Python-based detection rules for AWS CloudTrail events.

## Project Overview:
This lab demonstrates how cloud audit events can be analyzed to identify potentially suspicious authentication activity and IAM policy modifications. It combines Python detection logic, CloudTrail-style JSON event samples, automated unit tests, and investigation documentation.

## Objectives:
- Develop custom detection logic for selected AWS security events.
- Analyze CloudTrail event fields using Python.
- Validate detection behavior through positive and negative test cases.
- Document investigation steps, findings, and detection limitations.
- Build practical cloud detection engineering skills.

## Detection Rules:
- **AWS-LOGIN-001:** Detects repeated failed AWS console sign-in attempts from the same source IP within a five-minute window.
- **AWS-IAM-002:** Identifies selected IAM policy modification events for further investigation.

## Technologies
- Python
- AWS CloudTrail
- JSON
- Python `unittest`
- AWS Management Console

## Validation Status:
The current automated test suite contains **5 passing tests** across the two detection rules.
The positive detection scenarios use synthetic CloudTrail-style events. A sanitized real OAuth authorization event is included as a negative test. Live validation against matching real failed sign-in and IAM policy modification events remains outstanding.

## Repository Contents:
- `Src/` — Python detection implementations.
- `Sample_events/` — Synthetic event fixtures and a sanitized real event.
- `Tests/` — Automated unit tests.
- `Detections/` — Detection rule documentation.
- `Reports/` — Test validation and investigation reports.
- `Docs/` — Project architecture documentation.

## Security Notice
This project is an educational detection engineering lab. It does not automatically block users, change IAM permissions, or remediate AWS resources. Do not publish credentials, unredacted CloudTrail records, account identifiers, or other sensitive information.

## Future Improvements

- Add additional cloud detection rules.
- Expand edge-case and malformed-event testing.
- Improve structured finding output.
- Validate detection logic against appropriately authorized real CloudTrail events.
