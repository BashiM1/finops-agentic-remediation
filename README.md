# FinOps Agentic Remediation Engine

Governance and execution backend for serverless cloud cost remediation.

For what this system is and is not, read [`SCOPE.md`](./SCOPE.md) first.

## Architecture

The system is one Pulumi program (`__main__.py`) plus three Lambda packages
under `lambdas/`. There is no application server. See
[`docs/architecture.mermaid`](./docs/architecture.mermaid) for the
component-level flow.

## Lifecycle

A single remediation traverses five stages:

1. **Event ingestion.** A cost-anomaly event lands on an EventBridge bus and
   matches a rule that starts a Step Functions execution.
2. **Bedrock analysis.** The state machine invokes Anthropic Claude Haiku 4.5
   on Amazon Bedrock (`eu.anthropic.claude-haiku-4-5-20251001-v1:0`) to
   classify the anomaly and produce a human-readable risk summary.
3. **Slack approval.** A Block Kit card is posted via incoming webhook with
   an embedded task token. The state machine waits on
   `lambda:invoke.waitForTaskToken` (24h timeout, 1h heartbeat).
4. **IAM-enforced execution.** Slack's button click hits API Gateway →
   HMAC verify → SQS → callback processor → resolves the task token →
   executor Lambda calls `ec2:StopInstances`. Both IAM and the executor
   re-check `Environment` and `FinOps-Managed` tags.
5. **Audit logging.** Every terminal state writes a record to the
   `finops-audit-ledger-<account>` S3 bucket. The completeness check
   (Athena gap query) joins Step Functions success against `PUT.OBJECT`
   access logs — see [`docs/compliance/SCC-7.2-Audit-Procedures.md`](./docs/compliance/SCC-7.2-Audit-Procedures.md).

## Tech Stack

| Layer | Technology |
|---|---|
| Infrastructure as Code | Pulumi (Python) |
| Orchestration | AWS Step Functions |
| Compute | AWS Lambda (×3: `slack_delivery`, `callback_processor`, `executor`) |
| Eventing | AWS EventBridge, SQS |
| State | DynamoDB (`FinOps-Approvers`, `FinOps-StateCache`) |
| Ingress | API Gateway (HTTP) |
| LLM | Amazon Bedrock — Claude Haiku 4.5 |
| Audit | S3 + Object Lock |
| Notifications | SNS, Slack incoming webhook |
| CI/CD | GitHub Actions, AWS OIDC federation |

## Security Properties

- **HMAC-SHA256 verification** on every Slack callback at the API Gateway boundary; failed requests are rejected before reaching Lambda (evidence: `evidence/05-hmac-rejection.json`, `evidence/06-cloudwatch-rejection-log.txt`).
- **IAM `HardDenyProduction`** statement (`__main__.py:345`) denies `ec2:StopInstances`/`TerminateInstances` on `Environment=Prod`. The `AllowSafeRemediation` statement (`__main__.py:359`) requires `FinOps-Managed=True`. Both are mirrored by a code-level tag re-check in `lambdas/executor/main.py:48`.
- **Prompt-injection boundary** between user-supplied event data and the Bedrock system prompt (XML-fenced, validated per ADR-0001).
- **Idempotent SQS consumer** — the callback processor treats `TaskTimedOut`, `TaskDoesNotExist`, and `InvalidToken` from `send_task_success` as success, so SQS redeliveries hitting an already-resolved token do not double-execute.
- **No long-lived AWS keys.** GitHub Actions deploys via OIDC; the trust policy is pinned to `BashiM1/finops-agentic-remediation` `main` (`__main__.py:196`).

## Quick Start

Pre-requisites: AWS profile `finops-lab` configured, Pulumi CLI, Python 3.11+, a Slack workspace with permission to install apps.

```bash
# Activate the project venv (Pulumi.yaml's virtualenv: venv)
source venv/bin/activate

# Deploy
pulumi stack select dev
pulumi up

# Seed an approver (required before Slack approval will succeed)
APPROVERS_TABLE=$(pulumi stack output approvers_table_name) \
  AWS_PROFILE=finops-lab \
  python scripts/seed_approvers.py <SLACK_USER_ID>

# Wire Slack: replace the request_url placeholder in slack-manifest.yaml
# with $(pulumi stack output slack_webhook_url) before installing the app.
```

To trigger an end-to-end run, post a synthetic anomaly to the EventBridge bus or start a Step Functions execution directly with `aws stepfunctions start-execution --state-machine-arn $(pulumi stack output state_machine_arn) --input '...'`. The artefacts in `evidence/` show what a successful run produces.

## Tests

```bash
pytest tests/unit/ -v                  # full unit suite
ruff check ./lambdas                   # uses ruff.toml exclusions for vendored deps
```

There is no integration suite. End-to-end validation is captured in `evidence/` and reproducible via the steps above.

## Evidence

`evidence/` contains numbered artefacts captured during the reference deployment. Each demonstrates a specific control or behaviour:

| File(s) | Proves |
|---|---|
| `00-baseline.png` | Pre-deploy account state |
| `01-unit-tests-green.png` | All unit tests pass |
| `02-pulumi-up-success.png`, `03-stack-outputs.txt` | Successful provision of 41 resources and stack outputs |
| `04-approvers-seeded.json` | Approver ledger populated and queryable |
| `05-hmac-rejection.json`, `06-cloudwatch-rejection-log.txt` | HMAC rejection at the gateway, logged in CloudWatch |
| `07-execution-running.json` | Step Functions execution active in `RequestHumanApproval` |
| `08-bedrock-success-and-slack-pending.json` | Bedrock analysis returned, Slack message pending approval |
| `09-slack_is_live.png`, `10-slack-full-bedrock-analysis.png` | Approval card delivered to Slack with the LLM analysis |
| `11-end-to-end-succeeded.json`/`.png`, `12-execution-final-status.json` | Approved execution completes, state machine reaches `SUCCEEDED` |
| `13-pipeline-green.png` | DevSecOps pipeline (ruff → pytest → Snyk → Checkov → Pulumi up via OIDC) clean |
| `13-sqs-idempotency-stress-test.txt` | SQS redeliveries do not double-execute |

## Architecture Decision Records

Existing:

- [`0001-choice-of-llm.md`](./docs/adr/0001-choice-of-llm.md) — why Claude Haiku 4.5, and the per-deploy model-validation contract.
- [`0002-snyk-hybrid-security.md`](./docs/adr/0002-snyk-hybrid-security.md) — Snyk Code + SCA + Checkov composition, why all three.
- [`0003-object-lock-deviation.md`](./docs/adr/0003-object-lock-deviation.md) — why Object Lock is intentionally disabled in dev.

Scope-boundary ADRs (added with this documentation pass):

- [`ADR-001-discovery-vs-execution.md`](./docs/adr/ADR-001-discovery-vs-execution.md) — why discovery is upstream and out of scope.
- [`ADR-002-opt-in-resource-enrolment.md`](./docs/adr/ADR-002-opt-in-resource-enrolment.md) — why `FinOps-Managed=True` is required, not assumed.
- [`ADR-003-async-callback-processing.md`](./docs/adr/ADR-003-async-callback-processing.md) — why the Slack callback path is split across API Gateway, SQS, and a consumer Lambda.

## Related Projects

- **[`cost-gate`](https://github.com/BashiM1/cost-gate)** — the upstream sibling. A FastAPI service on GCP Cloud Run that ingests Terraform plans, estimates per-resource monthly cost via the AWS Pricing API and the GCP Billing Catalog, and surfaces breaches as PR comments. The two repos share no code; they are connected operationally via the `REMEDIATION_EVENT_BUS_ARN` environment variable and the same Slack workspace.

## Compliance

The stack targets **SOC 2 / SCC 7.2** non-repudiation. The completeness assertion is the Athena gap query in [`docs/compliance/SCC-7.2-Audit-Procedures.md`](./docs/compliance/SCC-7.2-Audit-Procedures.md): any Step Functions `SUCCEEDED` execution without a corresponding `PUT.OBJECT` on the audit-ledger bucket is a finding.

This is a **reference implementation**. The control families are designed to map to SCC 7.2 — alignment is by design intent, not by audit certification. See [`SCOPE.md`](./SCOPE.md) for what would be required to promote the deployment to production.
