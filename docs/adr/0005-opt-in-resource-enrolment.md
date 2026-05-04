# ADR 0005: Opt-in Resource Enrolment via Tags

## Status

Accepted (2026-04-25)

## Context

A remediation engine that can stop EC2 instances has unbounded blast radius unless its scope is constrained. The constraint mechanism must satisfy three properties: (1) it cannot be bypassed by an application bug, (2) it cannot be bypassed by misconfiguration of a single component, and (3) it is observable — an operator must be able to ask "is this resource in scope?" and get a definitive answer.

Application-level checks alone fail (1). Static allow-lists in code or DynamoDB fail (1) and (2). The constraint must be enforced at AWS's authorisation boundary.

## Decision

Resources must carry the tag `FinOps-Managed=True` to be remediable. The tag is an IAM `Condition` on the executor role's `AllowSafeRemediation` statement (`__main__.py:359`); without the tag, no matching Allow exists and AWS denies the API call by default. A separate `HardDenyProduction` statement (`__main__.py:345`) explicitly denies action against `Environment=Prod` resources, providing a second IAM gate that fires regardless of any other Allow.

The executor Lambda re-checks both tags in code (`lambdas/executor/main.py:48`–`77`) before issuing the API call. This is defence in depth, not redundancy: the IAM check protects against application bugs, the code check provides an early, auditable rejection point with a meaningful error message rather than a generic AWS `AccessDenied`.

## Alternatives Considered

- **Act on all resources by default.** Rejected — unbounded blast radius. A bug in event matching could stop arbitrary production instances.
- **Application-level allow-list (DynamoDB).** Rejected — a Lambda bug or a missing lookup short-circuits the gate, and there is no IAM-level evidence trail for auditors.
- **Organization-level resource tag policy (SCP).** Considered for production. Rejected for this reference implementation because Organization tag policies require AWS Organizations and an SCP layer, which is out of scope for a single-account demo. A production deployment should layer a tag policy on top of this IAM constraint.

## Consequences

- Resources not tagged are invisible to the engine. Coverage is a governance concern (provisioning standards, tag policies, infrastructure-as-code defaults), not an execution concern.
- Adding a new in-scope resource is a tag operation, not a code change. The engine does not need to be redeployed.
- Two-layer enforcement means a single misconfiguration — an over-broad IAM Allow, a missed code branch — does not silently expand scope.
- The cost-gate sibling repo deploys test resources tagged `FinOps-Managed=True, Environment=Dev` so the executor's allow path can be exercised end-to-end without touching anything tagged Prod.
