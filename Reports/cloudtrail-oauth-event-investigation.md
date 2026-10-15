# CloudTrail Investigation: OAuth Authorization Event

## 1. Investigation Summary:
- **Event name:** `AuthorizeOAuth2Access`
- **Event source:** `signin.amazonaws.com`
- **Event category:** Management
- **Event type:** `AwsApiCall`
- **Read-only:** Yes
- **Reported outcome:** Successful
- **MFA context:** The event's session context reported MFA as authenticated.

## 2. Observed Event Details:
The reviewed CloudTrail event recorded an OAuth authorization action. Its request parameters included an OpenID scope, a redirect URI, a SHA-256 code challenge method, and an AWS sign-in client identifier.
Sensitive identifiers, the source IP address, and the redirect URI have been redacted from the sanitized sample stored in this repository.

## 3. Security Assessment:
The event documents a successful OAuth authorization operation. By itself, it does not establish that the activity was malicious or unauthorized.
The presence of a successful result and an MFA-authenticated session is useful context, but neither independently proves that the action was legitimate.

## 4. Investigation Recommendations:
1. Confirm whether the authorization action was expected.
2. Review nearby CloudTrail events for related authentication or authorization activity.
3. Verify the application or workflow associated with the authorization, where possible.
4. Escalate only if additional evidence or organizational context indicates suspicious activity.

## 5. Detection Engineering Relevance:
This event was used as a negative test for `AWS-IAM-002`. The detector correctly generated no finding because `AuthorizeOAuth2Access` is not one of the IAM policy modification event names covered by that rule.
It was not a failed console sign-in and was not evidence of an IAM policy modification.

## 6. Limitations:
This assessment is based on one reviewed event and its sanitized representation. It does not establish whether other related activity occurred or whether the broader account is secure. The event was not treated as a confirmed security incident.
Sensitive raw event data is intentionally excluded from this report.
