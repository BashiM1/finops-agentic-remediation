"""
Callback processor Lambda.

Triggered by SQS messages from the slack-gateway-lambda after HMAC
verification has succeeded. Performs the heavier work that doesn't
need to fit inside Slack's 3-second response window:
  - DynamoDB approver lookup
  - SendTaskSuccess or SendTaskFailure to Step Functions

Idempotency: SQS may deliver a message more than once. Step Functions
SendTaskSuccess on an already-completed token returns TaskTimedOut or
TaskDoesNotExist, which we treat as success (the work is done).
"""

import json
import logging
import os

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

dynamodb = boto3.resource("dynamodb")
sfn = boto3.client("stepfunctions")

APPROVERS_TABLE_NAME = os.environ["APPROVERS_TABLE"]
approvers_table = dynamodb.Table(APPROVERS_TABLE_NAME)


def lookup_approver(user_id: str) -> dict | None:
    """Return approver record if user is ACTIVE, else None."""
    try:
        response = approvers_table.get_item(Key={"slack_user_id": user_id})
    except ClientError as e:
        logger.error(
            "DynamoDB lookup failed for user %s: %s", user_id, e
        )
        return None

    item = response.get("Item")
    if not item:
        logger.warning("No approver record found for user %s", user_id)
        return None

    if item.get("status") != "ACTIVE":
        logger.warning(
            "Approver %s is not ACTIVE (status=%s)",
            user_id,
            item.get("status"),
        )
        return None

    return item


def send_task_result(
    task_token: str,
    decision: str,
    authorized_by: str,
) -> None:
    """Resume the Step Functions execution with the approval result."""
    output = json.dumps({
        "AuthorizedBy": authorized_by,
        "Decision": decision,
    })
    try:
        sfn.send_task_success(taskToken=task_token, output=output)
        logger.info(
            "Sent task success: decision=%s, user=%s",
            decision,
            authorized_by,
        )
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        # These errors mean the token is already resolved or expired.
        # Treat as success (idempotency: the work is done).
        if error_code in ("TaskTimedOut", "TaskDoesNotExist", "InvalidToken"):
            logger.info(
                "Task token already resolved (%s); treating as success",
                error_code,
            )
            return
        logger.error("send_task_success failed: %s", e)
        raise


def send_task_rejection(task_token: str, reason: str) -> None:
    """Resume the Step Functions execution with a rejection."""
    try:
        sfn.send_task_failure(
            taskToken=task_token,
            error="ApprovalRejected",
            cause=reason,
        )
        logger.info("Sent task failure: %s", reason)
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code")
        if error_code in ("TaskTimedOut", "TaskDoesNotExist", "InvalidToken"):
            logger.info(
                "Task token already resolved (%s); treating as success",
                error_code,
            )
            return
        logger.error("send_task_failure failed: %s", e)
        raise


def process_callback(message_body: dict) -> None:
    """Process a single Slack callback message from SQS."""
    task_token = message_body["task_token"]
    decision = message_body["decision"]
    user_id = message_body["user_id"]

    logger.info(
        "Processing callback: user=%s, decision=%s",
        user_id,
        decision,
    )

    approver = lookup_approver(user_id)
    if approver is None:
        send_task_rejection(
            task_token,
            f"User {user_id} is not an authorised approver",
        )
        return

    if decision == "APPROVED":
        send_task_result(task_token, "APPROVED", user_id)
    elif decision == "REJECTED":
        send_task_rejection(task_token, f"Rejected by {user_id}")
    else:
        logger.error("Unknown decision: %s", decision)
        send_task_rejection(
            task_token,
            f"Invalid decision value: {decision}",
        )


def lambda_handler(event: dict, context) -> dict:
    """SQS event handler. Processes each record in the batch."""
    logger.info("Received %d records", len(event.get("Records", [])))

    for record in event.get("Records", []):
        try:
            body = json.loads(record["body"])
            process_callback(body)
        except Exception as e:
            logger.error(
                "Failed to process record: %s. Record: %s",
                e,
                record,
            )
            # Re-raise so SQS marks the message as failed
            # and retries (eventually to DLQ after maxReceiveCount).
            raise

    return {"statusCode": 200}