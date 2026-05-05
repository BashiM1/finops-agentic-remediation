# Post-Mortems

Three bugs from the build, written up so the same class doesn't recur.
Format: Summary, Timeline, Root Cause, Fix, Lessons Learned.

---

## PM-1: Environment variable name drift between IaC and Lambda code

**Summary.** The `callback_processor` Lambda crashed on its first real invocation because it read `APPROVERS_TABLE_NAME` from the environment, while Pulumi set `APPROVERS_TABLE`. No call ever made it past Lambda init.

**Timeline (2026-04-25, all times UTC).**
- T+0 — `pulumi up` reported success. CloudWatch showed init succeeding for both Lambdas in the approval path.
- T+~5 min — first Slack approval clicked; SQS message enqueued; processor Lambda invoked.
- T+~5 min 02 s — invocation failed with `KeyError: 'APPROVERS_TABLE_NAME'`. Step Functions execution sat in `RequestHumanApproval` until heartbeat timeout because no `SendTaskSuccess` ever fired.
- T+~12 min — diff between IaC env block (`__main__.py`) and Lambda env reads (`callback_processor/handler.py`) identified the name mismatch.
- T+~17 min — Lambda code changed to read `APPROVERS_TABLE`; `pulumi up`; replayed an approval; flow resumed.

**Root Cause.** Environment variable names were declared independently in two places: the Pulumi `FunctionEnvironmentArgs.variables` block and the Lambda's `os.environ` reads. No shared definition, no compile-time check that they agreed.

**Fix.** Renamed the Lambda's read to match the IaC. Trivially reactive; the right long-term fix is to remove the duplication.

**Lessons Learned.**
- Env-var names are an interface between two artefacts (IaC and runtime code) maintained in different languages. Like any cross-artefact interface, they need a single source of truth or a test that exercises both ends together.
- Local Lambda tests with mocked env vars cannot catch this — only a deploy + real-event invocation does. Adding a smoke test that posts a synthetic SQS message after every `pulumi up` would have caught it in seconds.
- A constants module shared between IaC and Lambda (`shared/env_keys.py`) imported on both sides removes the class.

---

## PM-2: DynamoDB attribute case drift across IaC, seed script, and handler

**Summary.** Three separate "field name disagreement" bugs surfaced inside 30 minutes after PM-1 was fixed. The first: the handler read `item.get("Status")` but the table stored `status`. Each subsequent invocation hit the next mismatch.

**Timeline (2026-04-25, ~1 hour after PM-1 closed).**
- T+0 — first approval after PM-1 fix. Handler retrieved a row, `item.get("Status")` returned `None`, ACTIVE check failed, approver rejected as inactive even though `seed_approvers.py` had populated them.
- T+~5 min — fix applied (`Status` → `status`); next attempt revealed `slack_user_id` vs `SlackUserId`.
- T+~15 min — third drift on a related field.
- T+~30 min — every read in the handler matched what the seed script wrote and what the table actually held.

**Root Cause.** The DynamoDB row shape was *implicitly* defined three times: in IaC (table attribute names where they appear in queries / GSIs), in the seed script (`scripts/seed_approvers.py`), and in the handler (`callback_processor/handler.py`). No type, no schema, no contract — three loose copies of the same dictionary keys, drifting independently.

**Fix.** Each occurrence matched against the table's actual contents. Same anti-pattern as PM-1: reactive, not structural.

**Lessons Learned.**
- Three bugs of the same shape in 30 minutes is one *class* of bug, not three bugs. The right response is to remove the class, not to patch each instance.
- Shared schema definition kills this entire class. Options that fit this stack: a Python dataclass per item type with `to_dynamodb_item` / `from_dynamodb_item` methods, a pydantic model with `model_dump` / `model_validate`, or a JSON Schema referenced by both Pulumi (via `aws.dynamodb.Table.attribute`) and the handlers.
- Until shared schemas land, a round-trip unit test (seed → query → assert handler-shaped result) is the cheapest mitigation.

---

## PM-3: OIDC deploy role missing `lambda:ListVersionsByFunction`

**Summary.** First deploy attempt from GitHub Actions via OIDC failed in Pulumi's diff phase. Local `pulumi up` had been succeeding because the developer's admin profile masked the missing permission.

**Timeline (2026-04-26).**
- T+0 — initial pushes to `main` deployed cleanly from a local workstation using a personal AWS profile (effectively `*`).
- T+later — OIDC deployer role wired up; first GH Actions deploy run started.
- T+~30 s — Pulumi step failed during diff with `User: arn:aws:sts::…:assumed-role/finops-deployer-role/… is not authorized to perform: lambda:ListVersionsByFunction`.
- T+~10 min — `lambda:ListVersionsByFunction` added to the deployer role's inline policy. Re-ran the workflow.
- T+~12 min — deploy succeeded.

**Root Cause.** Pulumi's diff phase calls more APIs than the declared resource set strictly needs. To detect Lambda *code* drift it calls `ListVersionsByFunction`. The OIDC deployer policy had been written by enumerating the obvious CRUD actions on each resource type (`lambda:CreateFunction`, `…UpdateFunctionCode`, `…DeleteFunction`, etc.) — list-style introspection actions weren't in that mental model. Locally, an admin profile silently included them.

**Fix.** Added `lambda:ListVersionsByFunction` to the deployer policy.

**Lessons Learned.**
- Deploy from CI on day one with a stub stack, before any real resources accumulate. Permission gaps surface before they're expensive to fix and before the engineer's mental model has hardened around "it works locally".
- IaC tools make implicit API calls beyond the resources you've declared. Auditing the exact action set requires either reading the provider source or running with CloudTrail open and a permissive policy, then extracting the actual call list with IAM Access Analyzer's policy generation.
- Iterating IAM via the error-message feedback loop ("add the action that this run complained about; rerun") produces partial permissions that are correct for the last run, not the next one. Generate the policy from observed calls instead.
