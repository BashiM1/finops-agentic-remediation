"""finops-followup-notifier Lambda.

Invoked by EventBridge Scheduler `review_after_days` after a PR merge
breached the cost-gate threshold. Receives the original event detail
as its `event` payload (the scheduler put it in the Target.Input),
formats a Block Kit follow-up, and POSTs to the Slack incoming
webhook stored in Secrets Manager.

Stays minimal on purpose — no buttons, no callback flow. Promoting
this to a remediation-approval card is P2.
"""
import json
import os
import urllib.request
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

secretsmanager = boto3.client("secretsmanager", region_name="eu-west-2")

SLACK_WEBHOOK_SECRET_ARN = os.environ["SLACK_WEBHOOK_SECRET_ARN"]

_webhook_cache: str | None = None


def _get_webhook_url() -> str:
    """Cache the webhook for the lifetime of the warm container."""
    global _webhook_cache
    if _webhook_cache is None:
        resp = secretsmanager.get_secret_value(SecretId=SLACK_WEBHOOK_SECRET_ARN)
        _webhook_cache = resp["SecretString"]
    return _webhook_cache


def _days_since(iso_timestamp: str | None) -> int:
    if not iso_timestamp:
        return 0
    try:
        merged = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    except ValueError:
        return 0
    delta = datetime.now(timezone.utc) - merged
    return max(int(delta.total_seconds() // 86400), 0)


def _build_blocks(detail: dict) -> list[dict]:
    pr_number = detail.get("pr_number")
    repository = detail.get("repository", "")
    author = detail.get("author", "")
    total = float(detail.get("total_monthly_cost_usd", 0))
    threshold = float(detail.get("threshold_usd_monthly", 0))
    days = _days_since(detail.get("merged_at"))
    pr_url = f"https://github.com/{repository}/pull/{pr_number}"

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"Cost Gate Follow-Up — PR #{pr_number} merged {days} day{'s' if days != 1 else ''} ago",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Repository*\n<https://github.com/{repository}|{repository}>"},
                {"type": "mrkdwn", "text": f"*Pull Request*\n<{pr_url}|#{pr_number}>"},
                {"type": "mrkdwn", "text": f"*Author*\n{author}"},
                {
                    "type": "mrkdwn",
                    "text": f"*Net Δ Monthly*\n${total:,.2f} (threshold ${threshold:,.2f})",
                },
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"Added *${total:,.2f}/mo* to infrastructure. Review recommended.",
            },
        },
        {"type": "divider"},
    ]

    resources = detail.get("resources") or []
    if resources:
        rows = [
            (
                r.get("address", ""),
                r.get("cloud", ""),
                r.get("change_action", ""),
                f"${float(r.get('monthly_cost_usd', 0)):,.2f}",
                r.get("confidence", ""),
            )
            for r in resources
        ]
        header = ("Resource", "Cloud", "Action", "Δ Monthly", "Confidence")
        widths = [max(len(h), max(len(row[i]) for row in rows)) for i, h in enumerate(header)]
        header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(header))
        body_lines = ["  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)) for row in rows]
        text = "```\n" + "\n".join([header_line, *body_lines]) + "\n```"
        # Section text caps at 3000; truncate defensively.
        if len(text) > 2900:
            text = text[:2896] + "\n```"
        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": text}})

    blocks.append(
        {
            "type": "context",
            "elements": [{"type": "mrkdwn", "text": "Approval flow not wired yet (P2)."}],
        }
    )
    return blocks


def _post(webhook_url: str, blocks: list[dict], fallback_text: str) -> bool:
    payload = json.dumps({"text": fallback_text, "blocks": blocks}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except Exception as exc:
        # Log the type only — exception str may carry the URL.
        print(f"SLACK_POST_ERROR: {type(exc).__name__}")
        return False


def lambda_handler(event, _context):
    # Scheduler delivers the schedule's Input as the event itself.
    # event is the detail dict from the original CostGateThresholdExceeded.
    detail = event if isinstance(event, dict) else {}
    pr_number = detail.get("pr_number")
    repository = detail.get("repository", "")

    if pr_number is None or not repository:
        print(f"REJECT: missing pr_number/repository: {detail}")
        return {"status": "rejected"}

    try:
        webhook = _get_webhook_url()
    except ClientError as exc:
        print(f"SECRET_FETCH_ERROR: {type(exc).__name__}")
        raise

    fallback = f"Cost Gate follow-up for {repository} PR#{pr_number}"
    blocks = _build_blocks(detail)
    if not _post(webhook, blocks, fallback):
        # Raise so Scheduler records this as a failed invocation. The
        # schedule deletes itself afterwards either way (one-time +
        # ActionAfterCompletion=DELETE), but the Lambda metric reflects
        # the failure for alerting.
        raise RuntimeError("Slack webhook POST failed")

    print(f"NOTIFIED: pr={pr_number} repo={repository}")
    return {"status": "ok"}
