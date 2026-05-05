"""finops-followup-scheduler Lambda.

Subscribes to `CostGateThresholdExceeded` events on the FinOps hub bus
and creates a one-time EventBridge Scheduler entry that fires
`review_after_days` from now. The schedule's target is the
finops-followup-notifier Lambda; the schedule carries the original
event detail as its Input so the notifier needs no DynamoDB lookup.

Schedule names are deterministic per (repository, pr_number, head_sha)
so a duplicate event is a no-op (treated as already scheduled).
"""
import json
import os
import re
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError

scheduler = boto3.client("scheduler", region_name="eu-west-2")

NOTIFIER_LAMBDA_ARN = os.environ["NOTIFIER_LAMBDA_ARN"]
SCHEDULER_ROLE_ARN = os.environ["SCHEDULER_ROLE_ARN"]
SCHEDULE_GROUP_NAME = os.environ.get("SCHEDULE_GROUP_NAME", "default")

_NAME_SAFE = re.compile(r"[^a-zA-Z0-9_-]+")


def _schedule_name(repository: str, pr_number: int, head_sha: str) -> str:
    """Stable, EventBridge-Scheduler-legal name. Max 64 chars."""
    sha8 = (head_sha or "")[:8] or "nosha"
    raw = f"cost-gate-followup-{repository}-pr{pr_number}-{sha8}"
    cleaned = _NAME_SAFE.sub("-", raw).strip("-")
    return cleaned[:64]


def _at_expression(days: int) -> str:
    """EventBridge Scheduler one-time `at()` expression in UTC."""
    target = datetime.now(timezone.utc) + timedelta(days=days)
    # at(yyyy-mm-ddThh:mm:ss) — no timezone suffix, no fractional seconds.
    return f"at({target.strftime('%Y-%m-%dT%H:%M:%S')})"


def lambda_handler(event, _context):
    detail = event.get("detail") or {}
    pr_number = detail.get("pr_number")
    repository = detail.get("repository", "")
    head_sha = detail.get("head_sha", "")
    review_after_days = int(detail.get("review_after_days", 7))

    if pr_number is None or not repository:
        # Defensive: refuse to schedule without identity. Better to
        # surface the bad event than to create an unidentified schedule.
        print(f"REJECT: missing pr_number/repository in detail: {detail}")
        return {"status": "rejected", "reason": "missing pr_number or repository"}

    name = _schedule_name(repository, pr_number, head_sha)
    expression = _at_expression(review_after_days)

    try:
        resp = scheduler.create_schedule(
            Name=name,
            GroupName=SCHEDULE_GROUP_NAME,
            ScheduleExpression=expression,
            ScheduleExpressionTimezone="UTC",
            FlexibleTimeWindow={"Mode": "OFF"},
            ActionAfterCompletion="DELETE",
            State="ENABLED",
            Target={
                "Arn": NOTIFIER_LAMBDA_ARN,
                "RoleArn": SCHEDULER_ROLE_ARN,
                "Input": json.dumps(detail),
            },
            Description=(
                f"Cost-gate follow-up for {repository} PR#{pr_number}; "
                f"fires {review_after_days}d after merge."
            ),
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "ConflictException":
            print(f"NOOP: schedule {name} already exists (duplicate event)")
            return {"status": "duplicate", "schedule_name": name}
        print(f"CREATE_SCHEDULE_ERROR: code={code} name={name}")
        raise

    print(
        f"SCHEDULED: name={name} arn={resp.get('ScheduleArn')} "
        f"fire_at={expression} pr={pr_number}"
    )
    return {
        "status": "scheduled",
        "schedule_name": name,
        "schedule_arn": resp.get("ScheduleArn"),
        "fire_at": expression,
    }
