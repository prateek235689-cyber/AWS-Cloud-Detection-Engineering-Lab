# AWS Cloud Detection Engineering Lab — Architecture

## 1. Project Overview:
This project demonstrates a lightweight Python-based detection engine that analyzes CloudTrail-style JSON events, identifies selected security-relevant activity, and produces structured findings.

## 2. Architecture Flow:
```text
CloudTrail-Style JSON Events
            |
            v
   Event Sample Repository
            |
            v
     Python Detection Engine
            |
      +-----+-----+
      |           |
      v           v
AWS-LOGIN-001  AWS-IAM-002
      |           |
      +-----+-----+
            |
            v
    Structured Findings
            |
            v
 Investigation Guidance
            |
            v
 Automated Unit Tests
```

## 3. Main Components:
- **`sample_events/`** — Contains synthetic CloudTrail-style event fixtures and a sanitized real OAuth authorization event.
- **`src/detection_engine.py`** — Detects repeated failed AWS console sign-ins within a configurable time window.
- **`src/iam_detection.py`** — Identifies selected IAM policy modification events.
- **`detections/`** — Documents each detection rule, its logic, investigation steps, and limitations.
- **`tests/`** — Contains automated positive and negative test cases.
- **`reports/`** — Contains test validation and sanitized event investigation reports.

## 4. Detection Workflow:
1. Load a JSON event fixture.
2. Evaluate the event fields against the implemented detection criteria.
3. Generate a structured finding when the criteria match.
4. Run automated tests to verify expected positive and negative behavior.
5. Use the documented investigation guidance to assess any findings.

## 5. Current Validation Status:
The current automated test suite contains five passing tests across the two detection rules.
The positive detection cases use synthetic events. One sanitized real CloudTrail OAuth event is included as a negative test. Live validation against a real failed console sign-in or IAM policy modification event has not yet been established.

## 6. Security and Cost Considerations:
The current implementation is a local Python demonstration and does not automatically modify AWS resources or block access.
It does not require additional AWS services to execute the local tests. Any future integration with live AWS telemetry should use least-privilege access, appropriate data sanitization, and a cost review before enabling additional services.

## 7. Future Improvements
- Add more edge-case and malformed-event tests.
- Improve event parsing and missing-field handling.
- Add structured JSON output for findings.
- Introduce additional detection rules for suspicious AWS activity.
- Evaluate detections against appropriately authorized real CloudTrail events.
