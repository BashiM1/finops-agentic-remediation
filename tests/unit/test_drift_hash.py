"""
Unit tests for EC2 state drift hash calculation.

Uses unittest.mock to simulate EC2 API responses without
requiring AWS credentials or live EC2 instances.
"""
import sys
import os
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))


MOCK_INSTANCE_BASELINE = {
    'Reservations': [{
        'Instances': [{
            'State': {'Name': 'running'},
            'InstanceType': 't3.micro',
            'BlockDeviceMappings': [
                {'Ebs': {'VolumeId': 'vol-0111111111111111a'}}
            ],
            'IamInstanceProfile': {
                'Arn': 'arn:aws:iam::582600397173:instance-profile/finops-role'
            },
            'NetworkInterfaces': [
                {'NetworkInterfaceId': 'eni-0222222222222222b'}
            ]
        }]
    }]
}


@patch('lambdas.slack_delivery.main.ec2')
def test_hash_is_deterministic(mock_ec2):
    """Same instance state must produce identical hash on repeated calls."""
    from lambdas.slack_delivery.main import calculate_live_state_hash

    mock_ec2.describe_instances.return_value = MOCK_INSTANCE_BASELINE

    hash_1 = calculate_live_state_hash('i-0abcdef1234567890')
    hash_2 = calculate_live_state_hash('i-0abcdef1234567890')

    assert hash_1 is not None
    assert hash_1 == hash_2


@patch('lambdas.slack_delivery.main.ec2')
def test_hash_changes_on_eni_addition(mock_ec2):
    """Adding a network interface must change the hash (drift detected)."""
    from lambdas.slack_delivery.main import calculate_live_state_hash
    import copy

    baseline_state = copy.deepcopy(MOCK_INSTANCE_BASELINE)
    mock_ec2.describe_instances.return_value = baseline_state
    baseline_hash = calculate_live_state_hash('i-0abcdef1234567890')

    drifted_state = copy.deepcopy(MOCK_INSTANCE_BASELINE)
    drifted_state['Reservations'][0]['Instances'][0][
        'NetworkInterfaces'
    ].append({'NetworkInterfaceId': 'eni-0333333333333333c'})

    mock_ec2.describe_instances.return_value = drifted_state
    drifted_hash = calculate_live_state_hash('i-0abcdef1234567890')

    assert baseline_hash != drifted_hash


@patch('lambdas.slack_delivery.main.ec2')
def test_hash_changes_on_iam_profile_change(mock_ec2):
    """Changing the IAM instance profile must change the hash."""
    from lambdas.slack_delivery.main import calculate_live_state_hash
    import copy

    baseline_state = copy.deepcopy(MOCK_INSTANCE_BASELINE)
    mock_ec2.describe_instances.return_value = baseline_state
    baseline_hash = calculate_live_state_hash('i-0abcdef1234567890')

    drifted_state = copy.deepcopy(MOCK_INSTANCE_BASELINE)
    drifted_state['Reservations'][0]['Instances'][0][
        'IamInstanceProfile'
    ]['Arn'] = 'arn:aws:iam::582600397173:instance-profile/attacker-role'

    mock_ec2.describe_instances.return_value = drifted_state
    drifted_hash = calculate_live_state_hash('i-0abcdef1234567890')

    assert baseline_hash != drifted_hash


@patch('lambdas.slack_delivery.main.ec2')
def test_hash_returns_none_on_api_error(mock_ec2):
    """EC2 API failure must return None, not raise an exception."""
    from lambdas.slack_delivery.main import calculate_live_state_hash

    mock_ec2.describe_instances.side_effect = Exception("EC2 API unavailable")
    result = calculate_live_state_hash('i-0abcdef1234567890')

    assert result is None
