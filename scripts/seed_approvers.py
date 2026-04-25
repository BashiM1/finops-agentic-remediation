"""
Seeds the DynamoDB FinOps-Approvers table with an authorised Slack user.

Usage:
  APPROVERS_TABLE=$(pulumi stack output approvers_table_name) \
  AWS_PROFILE=finops-lab \
  python scripts/seed_approvers.py <YOUR_SLACK_USER_ID>

To find your Slack User ID:
  Slack → click your profile picture → View profile → 
  three-dot menu → Copy member ID
  Format: U followed by alphanumerics e.g. U012AB3CD
"""
import boto3
import sys
import os


def seed_approver(slack_user_id: str, table_name: str) -> None:
    dynamodb = boto3.resource(
        'dynamodb',
        region_name='eu-west-2'
    )
    table = dynamodb.Table(table_name)

    table.put_item(
        Item={
            'slack_user_id': slack_user_id,
            'role': 'Admin',
            'max_approval_limit_usd': 500,
            'status': 'ACTIVE'
        }
    )
    print(f"Identity seeded: {slack_user_id} → {table_name}")
    print(f"Role: Admin | Approval limit: $500 | Status: ACTIVE")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    slack_user_id = sys.argv[1]

    if not slack_user_id.startswith('U') or len(slack_user_id) < 8:
        print(f"Warning: '{slack_user_id}' does not look like a Slack user ID")
        print("Expected format: U followed by alphanumerics e.g. U012AB3CD")
        confirm = input("Continue anyway? (y/N): ")
        if confirm.lower() != 'y':
            sys.exit(1)

    table_name = os.environ.get('APPROVERS_TABLE', 'FinOps-Approvers')
    seed_approver(slack_user_id, table_name)
