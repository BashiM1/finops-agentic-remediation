import os
import time
import json
import hmac
import hashlib
import boto3
import urllib.parse
import urllib.request
import base64
import re
from aws_lambda_powertools.utilities import parameters

# ==============================================================================
# INITIALISATION
# ==============================================================================
dynamodb = boto3.resource('dynamodb', region_name='eu-west-2')
ec2 = boto3.client('ec2', region_name='eu-west-2')
sfn = boto3.client('stepfunctions', region_name='eu-west-2')
sqs = boto3.client('sqs', region_name='eu-west-2')

SLACK_SECRET_ARN = os.environ.get('SLACK_SECRET_ARN', '')
SLACK_WEBHOOK_SECRET_ARN = os.environ.get('SLACK_WEBHOOK_SECRET_ARN', '')
STATE_CACHE_TABLE = os.environ.get('STATE_CACHE_TABLE', 'FinOps-StateCache')
APPROVERS_TABLE = os.environ.get('APPROVERS_TABLE', 'FinOps-Approvers')

EC2_INSTANCE_ID_PATTERN = re.compile(r'^i-[0-9a-f]{8,17}$')

_slack_secret_cache = None
_slack_webhook_cache = None


def get_slack_secret():
    global _slack_secret_cache
    if _slack_secret_cache is None:
        _slack_secret_cache = parameters.get_secret(SLACK_SECRET_ARN, max_age=300)
    return _slack_secret_cache


def get_slack_webhook_url():
    global _slack_webhook_cache
    if _slack_webhook_cache is None:
        _slack_webhook_cache = parameters.get_secret(SLACK_WEBHOOK_SECRET_ARN, max_age=300)
    return _slack_webhook_cache


def verify_slack_signature(headers, raw_body, secret):
    """
    Cryptographically verifies the payload originated from Slack.
    Uses hmac.compare_digest (timing-safe). Rejects timestamps older
    than 300 seconds (replay attack prevention).
    """
    headers_lower = {k.lower(): v for k, v in headers.items()}
    slack_signature = headers_lower.get('x-slack-signature', '')
    slack_timestamp = headers_lower.get('x-slack-request-timestamp', '0')

    try:
        timestamp_int = int(slack_timestamp)
    except ValueError:
        return False

    if abs(time.time() - timestamp_int) > 300:
        print(f"SIGNATURE_REJECT: Timestamp drift {abs(time.time() - timestamp_int):.0f}s")
        return False

    sig_basestring = f"v0:{slack_timestamp}:{raw_body}"
    my_signature = 'v0=' + hmac.new(
        key=secret.encode('utf-8'),
        msg=sig_basestring.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(my_signature, slack_signature)


def calculate_live_state_hash(instance_id):
    """
    Compute SHA-256 hash of EC2 instance state for drift detection.
    Returns None on API error (defensive: empty result fails closed).
    """
    try:
        response = ec2.describe_instances(InstanceIds=[instance_id])
        if not response.get('Reservations') or not response['Reservations'][0].get('Instances'):
            return None
        instance = response['Reservations'][0]['Instances'][0]

        components = [
            str(instance.get('State', {}).get('Name', '')),
            str(instance.get('InstanceType', '')),
            str(instance.get('IamInstanceProfile', {}).get('Arn', '')),
            str(sorted([v.get('Ebs', {}).get('VolumeId', '') for v in instance.get('BlockDeviceMappings', [])])),
            str(sorted([eni.get('NetworkInterfaceId', '') for eni in instance.get('NetworkInterfaces', [])]))
        ]
        composite = '|'.join(components)
        return hashlib.sha256(composite.encode('utf-8')).hexdigest()
    except Exception as e:
        print(f"DRIFT_HASH_ERROR: {e}")
        return None


def post_to_slack(webhook_url, blocks, fallback_text):
    """
    POST a Block Kit message to a Slack incoming webhook.
    Returns True on 2xx, False otherwise.
    """
    payload = json.dumps({"text": fallback_text, "blocks": blocks}).encode('utf-8')
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={'Content-Type': 'application/json'},
        method='POST'
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return 200 <= resp.status < 300
    except Exception as e:
        print(f"SLACK_POST_ERROR: {e}")
        return False


def build_approval_blocks(instance_id, region, savings, analysis_text, task_token):
    """
    Construct Slack Block Kit message for human approval.
    Embeds task_token in the action_id so the callback handler can
    resolve the correct Step Functions execution.
    """
    return [
        {
            "type": "header",
            "text": {"type": "plain_text", "text": "FinOps Remediation Approval Required"}
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Instance:*\n`{instance_id}`"},
                {"type": "mrkdwn", "text": f"*Region:*\n{region}"},
                {"type": "mrkdwn", "text": f"*Estimated Monthly Saving:*\n${savings}"},
                {"type": "mrkdwn", "text": "*Action:*\nStop instance"}
            ]
        },
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*AI Analysis:*\n{analysis_text}"}
        },
        {
            "type": "actions",
            "block_id": f"finops_approval_{instance_id}",
            "elements": [
                {
                    "type": "button",
                    "style": "primary",
                    "text": {"type": "plain_text", "text": "Approve"},
                    "action_id": "approve_remediation",
                    "value": task_token
                },
                {
                    "type": "button",
                    "style": "danger",
                    "text": {"type": "plain_text", "text": "Reject"},
                    "action_id": "reject_remediation",
                    "value": task_token
                }
            ]
        }
    ]


def handle_outbound_delivery(event):
    """
    Handle direct invocation from Step Functions with a TaskToken.
    Posts the approval message to Slack via incoming webhook.
    """
    task_token = event.get('TaskToken', '')
    event_details = event.get('EventDetails', {})
    instance_id = event_details.get('InstanceId', '')
    region = event_details.get('Region', 'eu-west-2')
    savings = event_details.get('EstimatedMonthlySavings', 'unknown')
    bedrock_analysis = event.get('BedrockAnalysis', {})

    # Defensive validation
    if not task_token:
        return {"statusCode": 400, "body": "Missing TaskToken"}
    if not EC2_INSTANCE_ID_PATTERN.match(instance_id):
        return {"statusCode": 400, "body": "Invalid InstanceId"}

    # Extract analysis text from Bedrock response
    analysis_text = "(No analysis available)"
    try:
        body = bedrock_analysis.get('Body', {})
        content = body.get('content', [])
        if content and isinstance(content, list):
            analysis_text = content[0].get('text', analysis_text)
    except (AttributeError, KeyError, IndexError):
        pass

    # Persist task token mapping for callback resolution
    table = dynamodb.Table(STATE_CACHE_TABLE)
    table.put_item(Item={
        'TaskToken': task_token,
        'InstanceId': instance_id,
        'CreatedAt': int(time.time()),
        'TTL': int(time.time()) + 86400
    })

    blocks = build_approval_blocks(instance_id, region, savings, analysis_text, task_token)
    fallback = f"FinOps approval required for {instance_id}"
    webhook = get_slack_webhook_url()

    if post_to_slack(webhook, blocks, fallback):
        print(f"SLACK_DELIVERED: instance={instance_id}")
        return {"statusCode": 200, "body": "Delivered"}
    else:
        print(f"SLACK_DELIVERY_FAILED: instance={instance_id}")
        return {"statusCode": 500, "body": "Delivery failed"}


def handle_inbound_callback(event):
    """
    Handle HTTP callback from Slack button click via API Gateway.

    Verifies HMAC, then enqueues the callback for async processing
    on SQS. Returns 200 immediately to fit inside Slack's 3-second
    response window. The callback processor Lambda performs the
    heavier work (approver lookup, SendTaskSuccess) outside that window.
    """
    headers = event.get('headers', {})
    raw_body = event.get('body', '')
    if event.get('isBase64Encoded'):
        raw_body = base64.b64decode(raw_body).decode('utf-8')

    # Security boundary: HMAC stays here. The processor trusts SQS
    # messages because only an HMAC-verified request can produce one.
    secret = get_slack_secret()
    if not verify_slack_signature(headers, raw_body, secret):
        print("AUTH_REJECT: Invalid Slack signature")
        return {"statusCode": 401, "body": "Unauthorized"}

    # Parse Slack interactivity payload (URL-encoded form)
    parsed = urllib.parse.parse_qs(raw_body)
    payload_json = parsed.get('payload', ['{}'])[0]
    payload = json.loads(payload_json)

    user_id = payload.get('user', {}).get('id', '')
    actions = payload.get('actions', [])
    if not actions:
        return {"statusCode": 400, "body": "No actions"}

    action = actions[0]
    action_id = action.get('action_id', '')
    task_token = action.get('value', '')

    # Translate Slack action_id to internal decision verb
    if action_id == 'approve_remediation':
        decision = 'APPROVED'
    elif action_id == 'reject_remediation':
        decision = 'REJECTED'
    else:
        return {"statusCode": 400, "body": "Unknown action"}

    # Enqueue for async processing. The processor will look up the
    # approver in DynamoDB and resume Step Functions. Snake_case keys
    # match the contract defined in callback_processor/handler.py.
    queue_url = os.environ['CALLBACK_QUEUE_URL']
    message_body = json.dumps({
        "task_token": task_token,
        "decision": decision,
        "user_id": user_id,
    })

    try:
        sqs.send_message(QueueUrl=queue_url, MessageBody=message_body)
        print(f"CALLBACK_ENQUEUED: user={user_id}, decision={decision}")
    except Exception as e:
        # If SQS itself is broken we can't recover. Log and let Slack
        # see a 500 — that's correct because the request truly failed.
        print(f"SQS_ENQUEUE_FAILED: {e}")
        return {"statusCode": 500, "body": "Internal error"}

    return {"statusCode": 200, "body": "Received"}


def lambda_handler(event, context):
    """
    Dual-mode handler:
    - Direct invoke from Step Functions with TaskToken -> outbound delivery
    - HTTP request via API Gateway -> inbound callback
    """
    if 'TaskToken' in event:
        return handle_outbound_delivery(event)
    return handle_inbound_callback(event)