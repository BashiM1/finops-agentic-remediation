# ADR-001: Discovery vs Execution Scope Boundary

## Status

Accepted (2026-04-25)

## Context

Cost-management systems typically conflate two distinct functions: detecting waste (discovery) and acting on it (execution). The question for this engine was whether to build both, or to commit to one.

Discovery is broad, periodic, low-stakes, and tolerant of false positives — a mis-flagged "idle" instance costs a notification. Execution is narrow, event-driven, high-stakes, and intolerant of false positives — a wrong stop call costs an outage. The two functions have different change rates, different blast radii, and different confidence requirements. Operating both inside the same governance boundary concentrates the operational risk of every discovery bug onto the execution path.

## Decision

The engine performs **execution only**. Discovery is treated as an upstream concern. Cost-anomaly events arrive on the EventBridge bus from any source that can produce a matching event schema; the engine does not care which.

Five upstream sources are documented in [`SCOPE.md`](../../SCOPE.md) as integration paths: AWS Cost Anomaly Detection (native EventBridge), Compute Optimizer (poll-translate), Trusted Advisor (Business/Enterprise tier), CUR + Athena (custom queries), and Cloud Custodian (policy-as-code).

## Alternatives Considered

- **Build discovery into the engine.** Rejected — concentrates risk, couples release cadences (a discovery rule change becomes an execution-engine deploy), and forces a single team to own two materially different problem domains.
- **Couple to a single third-party discovery vendor.** Rejected — creates a vendor dependency in the governance layer, and the IAM / HMAC / audit controls would degrade to whatever the vendor's integration provides.

## Consequences

- The system cannot find waste on its own. If no upstream source emits events, no remediation runs.
- Discovery is a swappable component. Replacing the upstream source does not require redeploying the engine.
- Bugs in discovery cannot, by construction, escalate to executor IAM permissions. The trust boundary is at the EventBridge rule, not inside the discovery logic.
- The engine takes on the obligation of validating event schemas defensively at the rule level — anything matching the rule reaches Bedrock for analysis.
