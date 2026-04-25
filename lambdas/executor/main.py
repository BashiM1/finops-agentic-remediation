import boto3
import logging
import re
import json
import time

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ec2 = boto3.client('ec2', region_name='eu-west-2')
EC2_INSTANCE_ID_PATTERN = re.compile(r'^i-[0-9a-f]{8,17}$')


def lambda_handler(event, context):
    """
    Safe-kill executor Lambda.

    Invoked by Step Functions AFTER human approval via Slack.
    Implements defence-in-depth: IAM policy is the primary blast
    radius control, code-level tag check is the secondary control.

    Never terminates instances — only stops them (reversible).
    Production instances (Environment: Prod) are aborted at both
    IAM and code level.
    """
    instance_id = event.get('InstanceId', '')
    authorized_by = event.get('AuthorizedBy', 'unknown')

    logger.info(json.dumps({
        "event": "EXECUTION_REQUESTED",
        "instance_id": instance_id,
        "authorized_by": authorized_by,
        "timestamp": int(time.time())
    }))

    # Defence in depth: re-validate instance ID format post-SFN
    # (SFN payload could theoretically be modified by a compromised role)
    if not instance_id or not EC2_INSTANCE_ID_PATTERN.match(str(instance_id)):
        logger.error(json.dumps({
            "event": "EXECUTION_BLOCKED",
            "reason": "INVALID_INSTANCE_ID_FORMAT",
            "instance_id": instance_id
        }))
        raise ValueError(f"Invalid instance ID format: {instance_id}")

    # Code-level production shield (IAM is primary, this is secondary)
    try:
        tags_response = ec2.describe_tags(
            Filters=[{'Name': 'resource-id', 'Values': [instance_id]}]
        )
        tag_dict = {
            t['Key']: t['Value']
            for t in tags_response.get('Tags', [])
        }

        if tag_dict.get('Environment') == 'Prod':
            logger.critical(json.dumps({
                "event": "PRODUCTION_SHIELD_ACTIVATED",
                "instance_id": instance_id,
                "authorized_by": authorized_by,
                "reason": "Instance tagged Environment=Prod"
            }))
            return {
                "status": "ABORTED",
                "reason": "Production Shield Active",
                "instance_id": instance_id
            }

        if tag_dict.get('FinOps-Managed') != 'True':
            logger.warning(json.dumps({
                "event": "EXECUTION_BLOCKED",
                "reason": "Instance not tagged FinOps-Managed=True",
                "instance_id": instance_id
            }))
            return {
                "status": "ABORTED",
                "reason": "Instance not FinOps-Managed",
                "instance_id": instance_id
            }

    except Exception as e:
        logger.warning(json.dumps({
            "event": "TAG_CHECK_FAILED",
            "instance_id": instance_id,
            "error": str(e),
            "action": "Proceeding — relying on IAM boundary"
        }))

    # Execute the stop (reversible — not terminate)
    try:
        ec2.stop_instances(InstanceIds=[instance_id])

        logger.info(json.dumps({
            "event": "EXECUTION_SUCCESS",
            "action": "STOP",
            "instance_id": instance_id,
            "authorized_by": authorized_by,
            "timestamp": int(time.time())
        }))

        return {
            "status": "SUCCESS",
            "action": "STOP",
            "instance_id": instance_id,
            "authorized_by": authorized_by,
            "timestamp": int(time.time())
        }

    except Exception as e:
        logger.error(json.dumps({
            "event": "EXECUTION_FAILED",
            "action": "STOP",
            "instance_id": instance_id,
            "error": str(e)
        }))
        raise
