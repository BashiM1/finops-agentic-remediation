# Scope

## What This System Is

A governance and execution backend for cloud cost remediation actions. It accepts cost-anomaly events as input, performs LLM-assisted analysis via Amazon Bedrock (Claude Haiku 4.5, model ID `eu.anthropic.claude-haiku-4-5-20251001-v1:0`), requires HMAC-verified human approval via Slack, and executes IAM-constrained remediation against resources explicitly enrolled via the `FinOps-Managed=True` tag. The stack is built around SOC 2 / SCC 7.2 non-repudiation; alignment is by design intent.

## What This System Is Not

- **Not a discovery tool.** It does not detect waste, find idle resources, or identify cost anomalies. Discovery is assumed upstream — see *Discovery Integration* below.
- **Not a multi-action platform.** Current execution scope is `ec2:StopInstances` against a single instance per remediation. Additional actions are pluggable via the Step Functions state machine but are not implemented.
- **Not multi-tenant.** Single AWS account, single region (`eu-west-2`). The deploy OIDC trust policy pins to `BashiM1/finops-agentic-remediation` `main` (`__main__.py:196`).
- **Not production-deployed.** This is a reference implementation demonstrating the architectural pattern. SCC 7.2 alignment is by design intent, not by audit certification — the completeness Athena query in `docs/compliance/SCC-7.2-Audit-Procedures.md` describes the procedure but has not been validated by a third-party assessor.
- **Audit-ledger writes are not yet wired.** The `finops-audit-ledger-<account>` bucket, Object Lock configuration, and the IAM `Allow` granting `s3:PutObject` to the executor role (`__main__.py:403`) are all in place, but no Lambda currently calls `s3.put_object`. Until the executor (or a dedicated audit Lambda) emits a record on each terminal state, the completeness gap query would flag every successful execution as a finding. Tracked as a known gap; closing it is a precondition for any production claim about SCC 7.2 non-repudiation.

## Discovery Integration (Out of Scope; Future Work)

Cost-anomaly events arrive on the EventBridge bus. The decoupling between discovery and execution lets any of the following feed the same bus:

- **AWS Cost Anomaly Detection** — native EventBridge integration; the canonical short-term path.
- **AWS Compute Optimizer** — periodic right-sizing findings; requires a poller to translate them into events.
- **AWS Trusted Advisor** — Business/Enterprise support tier; idle-resource and right-sizing checks.
- **Cost and Usage Reports + Athena** — custom waste signals (orphaned EBS, unused EIPs, oversized RDS).
- **Cloud Custodian** — policy-as-code engine for periodic scans; emits to EventBridge natively.

The separation is deliberate: discovery and execution have different cadences, blast radius, and confidence characteristics, and should not share a process boundary.

## Architectural Intent

- **Zero-trust ingress.** Every Slack callback is HMAC-verified at the API Gateway boundary. Direct Lambda invokes are not exposed publicly.
- **Defence in depth.** Approval requires HMAC signature verification *and* an `ACTIVE`-status entry in the `FinOps-Approvers` DynamoDB table. Execution is gated by an IAM `HardDenyProduction` deny on `Environment=Prod` resources (`__main__.py:345`), with the executor Lambda re-checking the tag in code as a secondary control (`lambdas/executor/main.py:56`). Neither IAM alone nor code alone is sufficient.
- **Async decoupling.** The inbound Slack callback returns 200 inside Slack's 3-second window by enqueuing the work to SQS; the heavier task-token resolution and remediation invocation happen on the consumer side.
- **IaC-defined.** All 41 deployed resources are managed by a single Pulumi Python program (`__main__.py`); no console-applied state.
- **OIDC federation.** GitHub Actions deploys via a Pulumi-managed AWS OIDC identity provider; no long-lived AWS keys exist in CI.

## What "Production-Grade" Means Here

The patterns are production-grade. The system as deployed is a reference implementation. Promoting it to production would require:

- A third-party SOC 2 / SCC 7.2 audit, with the completeness gap query in `docs/compliance/` re-run against real ledger data.
- Replacing the hardcoded Bedrock model ID (validated per-deploy per ADR-0001) with an SSM-parameter or app-config lookup, so model promotion does not require a Pulumi deploy.
- Multi-region failover for the executor and audit ledger; current `eu-west-2` pinning has no DR posture.
- Object Lock raised from disabled in dev (per ADR-0003) to `COMPLIANCE`/2555-day on the audit-ledger bucket.
- An incident-response runbook and on-call rotation for failed approvals, executor timeouts, and Bedrock-model deprecation events.
