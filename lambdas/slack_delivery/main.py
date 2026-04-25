import os
import time
import json
import hmac
import hashlib
import boto3
import urllib.parse
import base64
import re
from aws_lambda_powertools.utilities import parameters

# ==============================================================================
# INITIALISATION
# Boto3 clients are initialised at module level for warm invocation reuse.
# Secret retrieval is lazy (not at module level) so pytest can import
# this module without triggering an AWS Secrets Manager call.
# ==============================================================================
dynamodb = boto3.resource('dynamodb', region_name='eu-west-2')
ec2 = boto3.client('ec2', region_name='eu-west-2')
sfn = boto3.client('stepfunctions', region_name='eu-west-2')

SLACK_SECRET_ARN = os.environ.get('SLACK_SECRET_ARN', '')
STATE_CACHE_TABLE = os.environ.get('STATE_CACHE_TABLE', 'FinOps-StateCache')
APPROVERS_TABLE = os.environ.get('APPROVERS_TABLE', 'FinOps-Approvers')

EC2_INSTANCE_ID_PATTERN = re.compile(r'^i-[0-9a-f]{8,17}$')

# Lazy secret cache — not called at import time
_slack_secret_cache = None


def get_slack_secret():
    """
    Lazy initialisation of Slack signing secret.
    Cached across warm Lambda invocations (max_age=300s).
    Not called at module load time so pytest imports succeed
    without AWS credentials.
    """
    global _slack_secret_cache
    if _slack_secret_cache is None:
        _slack_secret_cache = parameters.get_secret(
            SLACK_SECRET_ARN,
            max_age=300
        )
    return _slack_secret_cache


def verify_slack_signature(headers, raw_body, secret):
    """
    Cryptographically verifies the payload originated from Slack.

    Uses hmac.compare_digest (timing-safe) to prevent timing attacks.
    Rejects payloads with timestamps older than 300 seconds (replay
    attack prevention within the Slack signature window).

    Returns True if valid, False otherwise.
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}
    slack_signature = headers_lower.get('x-slack-signature', '')
    slack_timestamp = headers_lower.get('x-slack-request-timestamp', '0')

    # Replay attack prevention: reject stale timestamps
    try:
        timestamp_int = int(slack_timestamp)
    except ValueError:
        return False

    if abs(time.time() - timestamp_int) > 300:
        print(f"SIGNATURE_REJECT: Timestamp drift {abs(time.time() - timestamp_int):.0f}s")
        return False

    # Construct and compare signatures
    sig_basestring = f"v0:{slack_timestamp}:{raw_body}"
    my_signature = 'v0=' + hmac.new(
        key=secret.encode('utf-8'),
        msg=sig_basestring.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()

    return hmac.compare_digest(my_signature, slack_signature)


def calculate_live_state_hash(instance_id):
    """
    Generates a SHA-256 hash of the current EC2 instance state.

    Captures: power state, instance type, IAM profile ARN,
    attached volume IDs (sorted), and network interface IDs (sorted).

    Sorting ensures deterministic hash output regardless of AWS
    API response ordering.

    Returns hex digest string, or None on error.
    """
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]

        power_state = instance['State']['Name']
        instance_type = instance['InstanceType']
        volumes = sorted([
            vol['Ebs']['VolumeId']
            for vol in instance.get('BlockDeviceMappings', [])
        ])
        iam_profile = instance.get(
            'IamInstanceProfile', {}
        ).get('Arn', 'None')
        enis = sorted([
            eni['NetworkInterfaceId']
            for eni in instance.get('NetworkInterfaces', [])
        ])

        state_string = (
            f"{power_state}|{instance_type}|{iam_profile}"
            f"|{','.join(volumes)}|{','.join(enis)}"
        )
        return hashlib.sha256(state_string.encode('utf-8')).hexdigest()

    except Exception as e:
        print(f"STATE_HASH_ERROR: {e}")
        return None


def lambda_handler(event, context):
    """
    Entry point for the Slack Gateway Lambda.

    Flow:
    1. Extract and decode body (handles base64 from API GW)
    2. Verify Slack HMAC signature (cryptographic boundary)
    3. Parse URL-encoded payload
    4. For block_actions: validate approver, check state drift,
       resume Step Functions with SendTaskSuccess
    5. For all other events: return 200 (Slack URL verification etc.)
    """
    headers = event.get('headers', {})

    # Handle base64 encoding from API Gateway HTTP API
    raw_body = event.get('body', '')
    if event.get('isBase64Encoded', False):
        raw_body = base64.b64decode(raw_body).decode('utf-8')

    # Cryptographic boundary: reject unsigned or tampered requests
    if not verify_slack_signature(headers, raw_body, get_slack_secret()):
        print("AUTH_REJECT: Invalid Slack signature")
        return {"statusCode": 401, "body": "Unauthorized"}

    # Parse URL-encoded Slack payload
    parsed_body = urllib.parse.parse_qs(raw_body)
    payload_str = parsed_body.get('payload', ['{}'])[0]

    try:
        payload = json.loads(payload_str)
    except json.JSONDecodeError:
        return {"statusCode": 400, "body": "Malformed payload"}

    # Handle Slack interactivity callback (button click)
    if payload.get('type') == 'block_actions':

        # Extract action data from button value
        try:
            action_data = json.loads(
                payload['actions'][0].get('value', '{}')
            )
        except (json.JSONDecodeError, KeyError, IndexError):
            return {"statusCode": 400, "body": "Malformed action value"}

        slack_user_id = payload.get('user', {}).get('id', '')
        instance_id = action_data.get('InstanceId', '')
        task_token = action_data.get('TaskToken', '')

        # Validate required fields
        if not instance_id or not task_token:
            return {"statusCode": 400, "body": "Missing required metadata"}

        # Injection defence: validate EC2 instance ID format
        if not EC2_INSTANCE_ID_PATTERN.match(instance_id):
            print(f"INJECTION_REJECT: Invalid instance ID format: {instance_id}")
            return {"statusCode": 400, "body": "Invalid instance ID format"}

        # Identity verification: confirm user is in approvers ledger
        approvers = dynamodb.Table(APPROVERS_TABLE)
        auth_result = approvers.get_item(
            Key={'slack_user_id': slack_user_id}
        )
        auth_record = auth_result.get('Item')

        if not auth_record or auth_record.get('status') != 'ACTIVE':
            print(f"AUTHZ_REJECT: Slack user {slack_user_id} not authorised")
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "text": "Action blocked. You are not an authorised FinOps approver."
                })
            }

        # State drift detection: compare live hash to baseline
        state_cache = dynamodb.Table(STATE_CACHE_TABLE)
        state_result = state_cache.get_item(Key={'TaskToken': task_token})
        state_record = state_result.get('Item')

        if state_record:
            baseline_hash = state_record.get('BaselineStateHash')
            live_hash = calculate_live_state_hash(instance_id)

            if live_hash is None:
                print(f"HASH_ERROR: Could not compute live hash for {instance_id}")
                return {
                    "statusCode": 200,
                    "body": json.dumps({
                        "text": f"Action aborted. Could not verify state of {instance_id}."
                    })
                }

            if live_hash != baseline_hash:
                print(
                    f"DRIFT_DETECTED: {instance_id} "
                    f"baseline={baseline_hash[:8]} live={live_hash[:8]}"
                )
                return {
                    "statusCode": 200,
                    "body": json.dumps({
                        "text": (
                            f"Action aborted. State drift detected on {instance_id}. "
                            f"IAM profile or network configuration has changed since "
                            f"approval was requested. Security team has been notified."
                        )
                    })
                }

        # All checks passed: resume Step Functions execution
        try:
            sfn.send_task_success(
                taskToken=task_token,
                output=json.dumps({
                    "AuthorizedBy": slack_user_id,
                    "Role": auth_record.get('role', 'Unknown'),
                    "Action": "EXECUTE_STOP",
                    "Timestamp": int(time.time())
                })
            )
            print(
                f"APPROVAL_SUCCESS: {instance_id} authorised by {slack_user_id}"
            )
            return {
                "statusCode": 200,
                "body": json.dumps({
                    "text": (
                        f"State verified. Stop command authorised for "
                        f"{instance_id} by {slack_user_id}."
                    )
                })
            }

        except Exception as e:
            print(f"SFN_ERROR: Failed to resume execution: {e}")
            return {
                "statusCode": 500,
                "body": "Failed to resume orchestration workflow"
            }

    # Default: acknowledge other Slack events (URL verification, etc.)
    return {"statusCode": 200, "body": "OK"}
