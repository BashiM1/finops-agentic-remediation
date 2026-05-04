# ADR 0006: Async Callback Processing via SQS

## Status

Accepted (2026-04-25)

## Context

Slack's interactivity API enforces a 3-second response window: an interactive component (button click, modal submit) must receive an HTTP 200 within 3 seconds, or Slack treats the interaction as failed and may retry. The approval flow needs to: (1) verify HMAC-SHA256, (2) look up the task token in `FinOps-StateCache`, (3) confirm the approver is `ACTIVE` in `FinOps-Approvers`, (4) call `SendTaskSuccess` against Step Functions. Steps 2–4 each involve cross-service AWS API calls, and 4 in particular has variable latency. End-to-end inside a single synchronous Lambda regularly exceeds 3 seconds under cold start.

## Decision

Split the callback path across two Lambdas with SQS between them.

The first Lambda (`slack_delivery` in inbound mode — `lambdas/slack_delivery/main.py:handle_inbound_callback`) does only HMAC verification and an SQS `SendMessage`, then returns 200 immediately. This is fast enough to fit inside the 3-second window even on a cold start.

The second Lambda (`callback_processor` — `lambdas/callback_processor/handler.py`) consumes from the SQS queue, performs the DynamoDB lookups, and calls `SendTaskSuccess`. It is invoked asynchronously by the SQS event source mapping and has no Slack-imposed deadline.

The SQS queue has a redrive policy: after three processing failures, messages move to a DLQ that publishes to the SNS escalation topic.

## Alternatives Considered

- **Single synchronous Lambda.** Rejected — cold-start latency plus four AWS calls regularly exceeds 3 seconds, and Slack will retry, causing duplicate `SendTaskSuccess` calls.
- **Self-invoking Lambda (return 200, re-invoke async).** Rejected — anti-pattern. Complicates IAM (the function needs to invoke itself), is harder to reason about during incidents, and the second invocation has no natural place to surface failures back to the user.
- **Increase Lambda timeout.** Rejected — orthogonal to the constraint. Slack's 3-second deadline applies to the inbound HTTP, regardless of Lambda configuration.

## Consequences

- Two Lambdas instead of one, with a queue between them. Increased operational surface area: two log groups, two metric sets, queue-depth and DLQ alarms.
- The consumer must be idempotent. SQS is at-least-once delivery and Slack itself may retry. The processor treats `TaskTimedOut`, `TaskDoesNotExist`, and `InvalidToken` from `send_task_success` as success rather than retrying — the second delivery hits an already-resolved token and should not error.
- Trust-boundary clarity: HMAC is verified before SQS enqueue. The processor consumes from a queue writeable only by the gateway-side Lambda's role, so it does not re-verify HMAC.
- Failures past three retries surface via DLQ → SNS, not via the user-facing Slack flow. A button click never appears to silently succeed.
