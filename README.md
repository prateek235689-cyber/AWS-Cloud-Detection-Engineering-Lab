# AWS Cloud Detection Engineering Lab

## Overview:
This project demonstrates a practical cloud detection engineering and incident investigation workflow using Amazon Web Services (AWS).
The lab focuses on analyzing AWS CloudTrail management events, developing detection logic for suspicious activity, validating detections against test events, and documenting safe incident response procedures.

## Objectives:
- Understand AWS CloudTrail event records.
- Develop detection logic for selected suspicious AWS API activities.
- Build repeatable test cases with documented expected outcomes.
- Investigate event evidence and construct incident timelines.
- Design least-privilege and controlled response workflows.
- Document findings, limitations, and remediation recommendations.

## Planned Technology Stack:
- AWS CloudTrail
- Python for event parsing and detection logic
- JSON-based event fixtures and test cases
- Amazon EventBridge and AWS Lambda for optional response automation
- Git and GitHub for version control and documentation

Services will be enabled only after checking availability, permissions, and potential charges.

## Project Methodology:
1. Review the lab scope and cost controls.
2. Inspect available CloudTrail management events.
3. Define detection use cases and expected outcomes.
4. Implement and test detection logic using sample events.
5. Investigate findings and document evidence.
6. Design a controlled response workflow.
7. Validate results and publish the final report.

## Repository Structure:
- `docs/` — architecture, methodology, and cost controls.
- `detections/` — detection use cases and rules.
- `sample-events/` — sanitized or synthetic test events.
- `investigations/` — investigation notes and timelines.
- `response/` — response workflow and safety controls.
- `tests/` — detection validation and test cases.
- `screenshots/` — selected evidence from completed lab activities.

## Safety and Cost Considerations:
This project uses only AWS resources and accounts for which the author has authorization. No real credentials, access keys, account-sensitive information, or confidential logs will be committed.

Potentially billable services will be reviewed before activation. Automated response actions will be tested in a controlled environment before any live remediation is considered.

## Project Status

**Status:** Initial setup

Implementation results, test outcomes, and screenshots will be added as each phase is completed. Planned features are not claimed as deployed or tested until verified.
