# FinOps Agentic Remediation Engine

Governance and execution backend for serverless cloud cost remediation.

For what this system is and is not, read [`SCOPE.md`](./SCOPE.md) first.
For trust boundaries and known findings, see [`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md).
For bugs encountered during the build and structural lessons, see [`docs/POST-MORTEMS.md`](./docs/POST-MORTEMS.md).

## Architecture

One Pulumi program (`__main__.py`) plus five Lambda packages under `lambdas/`. There is no application server. See [`docs/architecture.mermaid`](./docs/architecture.mermaid) for the component-level flow.

| Lambda | Role |
|---|---|
| `slack_delivery` | Dual-mode HMAC-verified gateway: outbound delivers approval cards via Slack incoming webhook, inbound verifies callbacks and enqueues to SQS within Slack's 3-second window. |
| `callback_processor` | SQS consumer. Resolves task tokens against `FinOps-StateCache`, validates the approver against `FinOps-Approvers`, calls `SendTaskSuccess`. Idempotent. |
| `executor` | Performs the approved action against EC2. Supports `stop` (reversible soft-kill) and `rightsize` (stop → ModifyInstanceAttribute → start). DRY_RUN-gated. |
| `followup_scheduler` | Subscribes to `CostGateThresholdExceeded` events from the cost-gate sibling on `finops-hub-bus`. Creates a one-time EventBridge Scheduler entry firing `review_after_days` from now. |
| `followup_notifier` | The scheduled target. Enriches the cost-gate event with Compute Optimizer findings (AWS) and GCP Recommender data (via reverse WIF), runs the result through Claude Haiku 4.5 for an AI assessment, then posts to Slack. |

## Lifecycles

The stack carries two independent flows.

### Anomaly remediation (the original path)

1. **Event ingestion.** A cost-anomaly event arrives on EventBridge and matches the SFN-trigger rule.
2. **Bedrock analysis.** The state machine invokes Claude Haiku 4.5 (`eu.anthropic.claude-haiku-4-5-20251001-v1:0`) for a 2-sentence financial-impact summary. A `INJECTION_DETECTED` canary handles overt prompt-injection attempts.
3. **Slack approval.** A Block Kit card with an embedded task token is posted via incoming webhook. The state machine waits on `lambda:invoke.waitForTaskToken` (24h timeout, 1h heartbeat).
4. **IAM-enforced execution.** Slack's button click hits API Gateway → HMAC verify → SQS → callback processor → resolves the task token → executor. The executor runs `stop` by default; the new `rightsize` action stops, modifies instance type, and restarts, with EC2 waiters between phases. `DRY_RUN=true` in dev gates the mutating calls; SNS escalation fires on any mid-flight failure.
5. **Audit logging.** Every terminal state should write to `finops-audit-ledger-<account>`. **Writer not yet implemented — see Known Gaps.**

### Cost-gate follow-up (the new path)

1. **Cost-gate emits.** The cost-gate service fires `CostGateThresholdExceeded` onto `finops-hub-bus` whenever a PR merges with cost above its configured threshold.
2. **Schedule.** `followup_scheduler` creates a one-time EventBridge Scheduler entry firing `review_after_days` (default 7) from now. The original event detail is the schedule's target Input.
3. **Fire.** When the schedule fires, EventBridge Scheduler invokes `followup_notifier` with the detail. The schedule self-deletes (`ActionAfterCompletion=DELETE`).
4. **Enrich.** The notifier queries Compute Optimizer per AWS instance and GCP Recommender per GCE zone. AWS→GCP federation is configured in cost-gate's `terraform/wif_aws_bridge.tf` — the AWS Lambda role federates into a GCP service account scoped to `roles/recommender.viewer`. Failures in either enricher are logged and continue; the Slack post is never blocked.
5. **Assess.** If at least one resource has actionable enrichment (`status=ok`), the trimmed payload is sent to Claude Haiku 4.5 for a 2-3 sentence FinOps analyst assessment. If every resource is `no_data` / `pending` / `skipped`, the Bedrock call is skipped — no token spend on empty data.
6. **Notify.** The notifier posts a Block Kit message: original cost breakdown, per-resource optimisation findings, the AI assessment block, footer.

## Tech Stack

| Layer | Technology |
|---|---|
| Infrastructure as Code | Pulumi (Python) |
| Orchestration | AWS Step Functions, EventBridge, EventBridge Scheduler |
| Compute | AWS Lambda (×5: see Architecture table) |
| Eventing | AWS EventBridge, SQS |
| State | DynamoDB (`FinOps-Approvers`, `FinOps-StateCache`) |
| Ingress | API Gateway (HTTP) |
| LLM | Amazon Bedrock — Claude Haiku 4.5 (analyst summary + follow-up assessment) |
| Cost intelligence | AWS Compute Optimizer, GCP Recommender (read-only via reverse WIF) |
| Audit | S3 + Object Lock |
| Notifications | SNS, Slack incoming webhook |
| CI/CD | GitHub Actions, AWS OIDC federation |

## Security Properties

- **HMAC-SHA256 verification** on every Slack callback at the API Gateway boundary; failed requests return 401 before reaching the consumer (`lambdas/slack_delivery/main.py:46-71`; evidence: `evidence/05-hmac-rejection.json`, `evidence/06-cloudwatch-rejection-log.txt`).
- **Dual-control IAM on remediation actions.** `HardDenyProduction` (`__main__.py:345`) denies `ec2:Stop/Terminate/Modify/StartInstances` on `Environment=Prod`; `AllowSafeRemediation` (`__main__.py:359`) requires `aws:ResourceTag/FinOps-Managed=True` on every action (now extended to cover `ec2:StartInstances` and `ec2:ModifyInstanceAttribute` for the `rightsize` path). Both are mirrored by an in-Lambda tag re-check (`lambdas/executor/main.py:_validate_tags`).
- **Prompt-injection canary** (not XML-fenced — see [`THREAT-MODEL.md`](./docs/THREAT-MODEL.md) §2). The Bedrock system prompt instructs the model to ignore embedded directives and emit `INJECTION_DETECTED` on attempts. User input is interpolated via `States.Format(...)` without structural delimiters; this is logged as a low-severity finding because the output is advisory and cannot bypass downstream approval and IAM gates.
- **Idempotent SQS consumer** — the callback processor treats `TaskTimedOut`, `TaskDoesNotExist`, and `InvalidToken` from `SendTaskSuccess` as success, so SQS redeliveries hitting an already-resolved token do not double-execute.
- **No long-lived cloud credentials.** GitHub Actions deploys via AWS OIDC; the trust policy is pinned to `BashiM1/finops-agentic-remediation` `main` (`__main__.py:196`). The follow-up notifier reaches GCP via Workload Identity Federation against an AWS-account-scoped pool with a per-role attribute condition; tokens are 1-hour STS leases.
- **Best-effort enrichment never blocks the user-facing path.** Compute Optimizer, GCP Recommender, and Bedrock failures all log and continue; the Slack notification always lands.
- **`rightsize` action gated by `DRY_RUN`.** Defaults to `true` in dev (Pulumi config `executorDryRun`); flipped to `false` only on demo day. SNS escalation fires on any mid-flight failure so an instance is never silently left stopped after a successful stop or modify.

## Quick Start

Pre-requisites: AWS profile `finops-lab` configured, Pulumi CLI, Python 3.11+, a Slack workspace with permission to install apps.

```bash
source venv/bin/activate
pulumi stack select dev
pulumi up

# Seed an approver (required before Slack approval will succeed)
APPROVERS_TABLE=$(pulumi stack output approvers_table_name) \
  AWS_PROFILE=finops-lab \
  python scripts/seed_approvers.py <SLACK_USER_ID>

# Wire Slack: replace the request_url placeholder in slack-manifest.yaml
# with $(pulumi stack output slack_webhook_url) before installing the app.
```

To trigger the original anomaly path: `aws stepfunctions start-execution --state-machine-arn $(pulumi stack output state_machine_arn) --input '...'` with synthetic event data, or post directly to the EventBridge bus the SFN rule listens on.

To trigger the follow-up path: `aws events put-events` with `Source=cost-gate, DetailType=CostGateThresholdExceeded` (or, end-to-end, merge a PR in the cost-gate sibling that breaches its threshold).

The artefacts in `evidence/` show what a successful run produces.

## Tests

```bash
pytest tests/unit/ -v
ruff check ./lambdas    # uses ruff.toml exclusions for vendored deps
```

There is no integration suite. End-to-end validation is captured in `evidence/`.

## Documentation

- [`SCOPE.md`](./SCOPE.md) — what this system is and is not. Read first.
- [`docs/architecture.mermaid`](./docs/architecture.mermaid) — component diagram with trust-boundary gates.
- [`docs/THREAT-MODEL.md`](./docs/THREAT-MODEL.md) — 7 trust boundaries, mitigations, residual findings.
- [`docs/POST-MORTEMS.md`](./docs/POST-MORTEMS.md) — three structural bugs from the build and the lessons they left.
- [`docs/compliance/SCC-7.2-Audit-Procedures.md`](./docs/compliance/SCC-7.2-Audit-Procedures.md) — the Athena gap query and how it would be run against ledger data.

### Architecture Decision Records

- [`0001-choice-of-llm.md`](./docs/adr/0001-choice-of-llm.md) — why Claude Haiku 4.5, and the per-deploy model-validation contract.
- [`0002-snyk-hybrid-security.md`](./docs/adr/0002-snyk-hybrid-security.md) — Snyk Code + SCA + Checkov composition, why all three.
- [`0003-object-lock-deviation.md`](./docs/adr/0003-object-lock-deviation.md) — why Object Lock is intentionally disabled in dev.
- [`0004-discovery-vs-execution.md`](./docs/adr/0004-discovery-vs-execution.md) — why discovery is upstream and out of scope.
- [`0005-opt-in-resource-enrolment.md`](./docs/adr/0005-opt-in-resource-enrolment.md) — why `FinOps-Managed=True` is required, not assumed.
- [`0006-async-callback-processing.md`](./docs/adr/0006-async-callback-processing.md) — why the Slack callback path is split across API Gateway, SQS, and a consumer Lambda.

## Evidence

`evidence/` contains numbered artefacts captured during the reference deployment. Each demonstrates a specific control or behaviour:

| File(s) | Proves |
|---|---|
| `00-baseline.png` | Pre-deploy account state |
| `01-unit-tests-green.png` | All unit tests pass |
| `02-pulumi-up-success.png`, `03-stack-outputs.txt` | Successful provision and stack outputs |
| `04-approvers-seeded.json` | Approver ledger populated and queryable |
| `05-hmac-rejection.json`, `06-cloudwatch-rejection-log.txt` | HMAC rejection at the gateway, logged in CloudWatch |
| `07-execution-running.json` | Step Functions execution active in `RequestHumanApproval` |
| `08-bedrock-success-and-slack-pending.json` | Bedrock analysis returned, Slack message pending approval |
| `09-slack_is_live.png`, `10-slack-full-bedrock-analysis.png` | Approval card delivered to Slack with the LLM analysis |
| `11-end-to-end-succeeded.json`/`.png`, `12-execution-final-status.json` | Approved execution completes, SFN reaches `SUCCEEDED` |
| `13-pipeline-green.png` | DevSecOps pipeline (ruff → pytest → Snyk → Checkov → Pulumi up via OIDC) clean |
| `13-sqs-idempotency-stress-test.txt` | SQS redeliveries do not double-execute |

## Related Projects

- **[`cost-gate`](https://github.com/BashiM1/cost-gate)** — the upstream sibling. A FastAPI service on GCP Cloud Run that ingests Terraform plans, estimates per-resource monthly cost via the AWS Pricing API and the GCP Billing Catalog, and surfaces breaches as PR comments. On merge above threshold it emits `CostGateThresholdExceeded` to the `finops-hub-bus` EventBridge bus that this engine consumes. The two repos share no code; they are connected operationally via the bus, the same Slack workspace, and the cross-cloud federation pools defined in cost-gate's `terraform/wif*.tf`.

## Compliance

The stack targets **SOC 2 / SCC 7.2** non-repudiation. The completeness assertion is the Athena gap query in [`docs/compliance/SCC-7.2-Audit-Procedures.md`](./docs/compliance/SCC-7.2-Audit-Procedures.md): any Step Functions `SUCCEEDED` execution without a corresponding `PUT.OBJECT` on the audit-ledger bucket is a finding.

**Known gap:** the audit-ledger *writer* is not yet implemented. The bucket, Object Lock configuration, and the IAM Allow on `s3:PutObject` (`__main__.py:403`) are in place, but no Lambda currently calls `s3.put_object`. Until that lands, the gap query would flag every successful execution. The `EXEC → LEDGER` edge in [`docs/architecture.mermaid`](./docs/architecture.mermaid) is rendered in dashed orange to mark it as planned. Logged as the highest-severity finding in `docs/THREAT-MODEL.md` §6.

This is a **reference implementation**. The control families are designed to map to SCC 7.2 — alignment is by design intent, not by audit certification. See [`SCOPE.md`](./SCOPE.md) for what would be required to promote the deployment to production.
