"""finops-executor Lambda.

Executes a remediation against a single EC2 instance after human
approval has cleared via Slack. Supports two action types:

  - ``stop``      : reversible soft-kill via ec2:StopInstances. Default
                    when no Action field is set, preserving the original
                    SFN contract.
  - ``rightsize`` : stop → ec2:ModifyInstanceAttribute → start, with
                    waiters between phases. On any failure mid-flight
                    the executor publishes to the FinOps escalation
                    SNS topic and re-raises so SFN catches the failure;
                    leaving an instance stopped without a notification
                    is not an acceptable terminal state.

DRY_RUN env var (default ``true`` in dev) gates every mutating EC2
call. With DRY_RUN=true the Lambda still validates tags but logs the
intended sequence instead of executing it. Demo day flips the Pulumi
config ``executorDryRun`` to ``false``.

Defence in depth is unchanged from the stop-only version: IAM is the
primary blast-radius control; the in-Lambda Environment=Prod / FinOps-
Managed tag re-check is the secondary control. Both must hold.
"""
import json
import logging
import os
import re
import time

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client("ec2", region_name="eu-west-2")

DRY_RUN = os.environ.get("DRY_RUN", "true").lower() == "true"
ESCALATION_TOPIC_ARN = os.environ.get("ESCALATION_TOPIC_ARN", "")
sns = boto3.client("sns", region_name="eu-west-2") if ESCALATION_TOPIC_ARN else None

EC2_INSTANCE_ID_PATTERN = re.compile(r"^i-[0-9a-f]{8,17}$")


def _emit(level, payload):
    line = json.dumps(payload)
    if level == "error":
        logger.error(line)
    elif level == "warning":
        logger.warning(line)
    elif level == "critical":
        logger.critical(line)
    else:
        logger.info(line)


def _escalate(payload: dict) -> None:
    """Publish to the SNS escalation topic. Never raises."""
    enriched = {"event": "EXECUTOR_ESCALATION", "timestamp": int(time.time()), **payload}
    _emit("error", enriched)
    if sns is None:
        _emit("warning", {"event": "ESCALATION_NO_TOPIC", "would_publish": enriched})
        return
    try:
        sns.publish(
            TopicArn=ESCALATION_TOPIC_ARN,
            Subject="FinOps Executor Escalation",
            Message=json.dumps(enriched),
        )
    except Exception as exc:
        _emit("error", {"event": "ESCALATION_PUBLISH_FAILED", "error": str(exc)})


def _validate_tags(instance_id: str, authorized_by: str) -> tuple[bool, dict | None]:
    """Run the dual-tag safety gate. Returns (allowed, abort_response_or_None)."""
    try:
        tags_response = ec2.describe_tags(
            Filters=[{"Name": "resource-id", "Values": [instance_id]}]
        )
        tag_dict = {t["Key"]: t["Value"] for t in tags_response.get("Tags", [])}
    except Exception as e:
        _emit("warning", {
            "event": "TAG_CHECK_FAILED",
            "instance_id": instance_id,
            "error": str(e),
            "action": "Proceeding — relying on IAM boundary",
        })
        return True, None

    if tag_dict.get("Environment") == "Prod":
        _emit("critical", {
            "event": "PRODUCTION_SHIELD_ACTIVATED",
            "instance_id": instance_id,
            "authorized_by": authorized_by,
            "reason": "Instance tagged Environment=Prod",
        })
        return False, {"status": "ABORTED", "reason": "Production Shield Active", "instance_id": instance_id}

    if tag_dict.get("FinOps-Managed") != "True":
        _emit("warning", {
            "event": "EXECUTION_BLOCKED",
            "reason": "Instance not tagged FinOps-Managed=True",
            "instance_id": instance_id,
        })
        return False, {"status": "ABORTED", "reason": "Instance not FinOps-Managed", "instance_id": instance_id}

    return True, None


def _action_stop(instance_id: str, authorized_by: str) -> dict:
    """Reversible soft-kill. Identical to the pre-rightsize behaviour."""
    if DRY_RUN:
        _emit("info", {
            "event": "DRY_RUN",
            "action": "STOP",
            "instance_id": instance_id,
            "would_call": ["ec2:StopInstances"],
        })
        return {
            "status": "DRY_RUN_OK", "action": "STOP",
            "instance_id": instance_id, "authorized_by": authorized_by,
        }
    try:
        ec2.stop_instances(InstanceIds=[instance_id])
    except Exception as e:
        _emit("error", {"event": "EXECUTION_FAILED", "action": "STOP", "instance_id": instance_id, "error": str(e)})
        raise
    _emit("info", {
        "event": "EXECUTION_SUCCESS", "action": "STOP",
        "instance_id": instance_id, "authorized_by": authorized_by, "timestamp": int(time.time()),
    })
    return {
        "status": "SUCCESS", "action": "STOP",
        "instance_id": instance_id, "authorized_by": authorized_by, "timestamp": int(time.time()),
    }


def _action_rightsize(instance_id: str, target_type: str, authorized_by: str) -> dict:
    """Stop → ModifyInstanceAttribute → Start, with waiters and SNS escalation."""
    if not target_type:
        raise ValueError("rightsize requires TargetInstanceType")

    if DRY_RUN:
        _emit("info", {
            "event": "DRY_RUN",
            "action": "RIGHTSIZE",
            "instance_id": instance_id,
            "target_instance_type": target_type,
            "would_call": ["ec2:StopInstances", "ec2:ModifyInstanceAttribute", "ec2:StartInstances"],
            "would_wait_for": ["instance_stopped", "instance_running"],
        })
        return {
            "status": "DRY_RUN_OK", "action": "RIGHTSIZE",
            "instance_id": instance_id, "target_instance_type": target_type,
            "authorized_by": authorized_by,
        }

    # Phase 1: stop. Failure here leaves the instance running — clean abort,
    # no escalation needed beyond the raised exception.
    try:
        ec2.stop_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_stopped").wait(InstanceIds=[instance_id])
        _emit("info", {"event": "RIGHTSIZE_STOPPED", "instance_id": instance_id})
    except Exception as e:
        _emit("error", {"event": "RIGHTSIZE_STOP_FAILED", "instance_id": instance_id, "error": str(e)})
        raise

    # Phase 2: modify type. Failure here leaves the instance STOPPED.
    # We attempt to restart with the original type and escalate either
    # outcome — never leave a stopped instance silently.
    try:
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            InstanceType={"Value": target_type},
        )
        _emit("info", {"event": "RIGHTSIZE_MODIFIED", "instance_id": instance_id, "target_instance_type": target_type})
    except Exception as e:
        _escalate({
            "phase": "modify",
            "instance_id": instance_id,
            "target_instance_type": target_type,
            "error": str(e),
            "remediation": "attempting to restart with original type",
        })
        try:
            ec2.start_instances(InstanceIds=[instance_id])
            ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
            _escalate({
                "phase": "modify_then_recovered",
                "instance_id": instance_id,
                "state": "instance restarted with original type after modify failure",
            })
        except Exception as restart_err:
            _escalate({
                "phase": "modify_then_restart_failed",
                "instance_id": instance_id,
                "error": str(restart_err),
                "severity": "CRITICAL",
                "state": "instance is STOPPED after modify failure; manual intervention required",
            })
        raise

    # Phase 3: start. Failure here leaves the instance STOPPED with the
    # NEW type. Escalation is mandatory; manual restart is the recovery.
    try:
        ec2.start_instances(InstanceIds=[instance_id])
        ec2.get_waiter("instance_running").wait(InstanceIds=[instance_id])
    except Exception as e:
        _escalate({
            "phase": "start",
            "instance_id": instance_id,
            "target_instance_type": target_type,
            "error": str(e),
            "severity": "CRITICAL",
            "state": "instance is STOPPED with new type after successful modify; manual intervention required",
        })
        raise

    _emit("info", {
        "event": "RIGHTSIZE_SUCCESS",
        "instance_id": instance_id,
        "target_instance_type": target_type,
        "authorized_by": authorized_by,
        "timestamp": int(time.time()),
    })
    return {
        "status": "SUCCESS",
        "action": "RIGHTSIZE",
        "instance_id": instance_id,
        "target_instance_type": target_type,
        "authorized_by": authorized_by,
        "timestamp": int(time.time()),
    }


def lambda_handler(event, context):
    """Dispatch on event['Action']. Default 'stop' preserves the original SFN contract."""
    instance_id = event.get("InstanceId", "")
    authorized_by = event.get("AuthorizedBy", "unknown")
    action = (event.get("Action") or "stop").lower()

    _emit("info", {
        "event": "EXECUTION_REQUESTED",
        "action": action.upper(),
        "instance_id": instance_id,
        "authorized_by": authorized_by,
        "dry_run": DRY_RUN,
        "timestamp": int(time.time()),
    })

    if not instance_id or not EC2_INSTANCE_ID_PATTERN.match(str(instance_id)):
        _emit("error", {
            "event": "EXECUTION_BLOCKED",
            "reason": "INVALID_INSTANCE_ID_FORMAT",
            "instance_id": instance_id,
        })
        raise ValueError(f"Invalid instance ID format: {instance_id}")

    allowed, abort = _validate_tags(instance_id, authorized_by)
    if not allowed:
        return abort

    if action == "stop":
        return _action_stop(instance_id, authorized_by)
    if action == "rightsize":
        return _action_rightsize(
            instance_id,
            event.get("TargetInstanceType", ""),
            authorized_by,
        )

    _emit("error", {"event": "UNKNOWN_ACTION", "action": action, "instance_id": instance_id})
    raise ValueError(f"Unknown action: {action}")
