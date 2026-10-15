# AWS Cloud Detection Engineering Lab — Test Validation Report

## 1. Overview:
This report documents the automated validation of two Python-based AWS CloudTrail detection rules.

- **AWS-LOGIN-001:** Repeated failed AWS console sign-ins.
- **AWS-IAM-002:** Selected IAM policy modification events.

## 2. Test Execution:
Command executed:

```cmd
python -m unittest discover -s tests -v
```

**Result:** 5 tests passed; 0 failures; 0 errors.

## 3. Test Results:
| Detection Rule | Test Scenario | Result |
|---|---|---|
| AWS-LOGIN-001 | Three failed sign-ins within five minutes | PASS |
| AWS-LOGIN-001 | Only two failed sign-ins | PASS |
| AWS-IAM-002 | IAM `PutUserPolicy` event | PASS |
| AWS-IAM-002 | Unrelated EC2 `DescribeInstances` event | PASS |
| AWS-IAM-002 | Sanitized OAuth authorization event | PASS |

## 4. Validation Scope:
The test suite validates the expected behavior of the implemented detection functions using synthetic CloudTrail-style events and a sanitized real CloudTrail OAuth event.
The OAuth event is a negative test because its event name does not match the IAM policy modification rule.

## 5. Limitations:
- The positive detection scenarios use synthetic data.
- No matching IAM policy modification event was found in the reviewed AWS CloudTrail event history.
- Live detection against real IAM policy modification events has not yet been validated.
- Passing tests do not prove that every possible attack pattern will be detected.
- These rules generate findings only; they do not automatically block access or modify AWS resources.

## 6. Conclusion:
Both detection functions passed their current automated test suites. Further validation using appropriately authorized, real CloudTrail events and additional edge-case tests would be needed before production use.
