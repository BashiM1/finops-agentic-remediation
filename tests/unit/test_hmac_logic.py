"""
Unit tests for HMAC signature verification.

These tests run without AWS credentials — the lazy secret
initialisation in main.py means importing verify_slack_signature
does not trigger a Secrets Manager call.
"""
import time
import hmac
import hashlib
import pytest
import sys
import os

# Add project root to path so imports work from tests directory
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))


def make_valid_signature(secret, timestamp, body):
    """Helper: generate a valid Slack signature for testing."""
    sig_basestring = f"v0:{timestamp}:{body}"
    return 'v0=' + hmac.new(
        key=secret.encode('utf-8'),
        msg=sig_basestring.encode('utf-8'),
        digestmod=hashlib.sha256
    ).hexdigest()


def test_verify_slack_signature_valid():
    """Valid signature with current timestamp should pass."""
    from lambdas.slack_delivery.main import verify_slack_signature

    secret = "test_secret_32chars_exactly_here"
    timestamp = str(int(time.time()))
    body = "payload=%7B%22type%22%3A%22block_actions%22%7D"
    valid_sig = make_valid_signature(secret, timestamp, body)

    headers = {
        'x-slack-signature': valid_sig,
        'x-slack-request-timestamp': timestamp
    }

    assert verify_slack_signature(headers, body, secret) is True


def test_verify_slack_signature_replay_attack():
    """Signature with timestamp older than 300s should be rejected."""
    from lambdas.slack_delivery.main import verify_slack_signature

    secret = "test_secret_32chars_exactly_here"
    stale_timestamp = str(int(time.time()) - 600)
    body = "payload=%7B%22type%22%3A%22block_actions%22%7D"
    stale_sig = make_valid_signature(secret, stale_timestamp, body)

    headers = {
        'x-slack-signature': stale_sig,
        'x-slack-request-timestamp': stale_timestamp
    }

    assert verify_slack_signature(headers, body, secret) is False


def test_verify_slack_signature_invalid_hash():
    """Tampered signature should be rejected."""
    from lambdas.slack_delivery.main import verify_slack_signature

    secret = "test_secret_32chars_exactly_here"
    timestamp = str(int(time.time()))
    body = "payload=%7B%22type%22%3A%22block_actions%22%7D"

    headers = {
        'x-slack-signature': 'v0=invalidsignaturethatwillfail',
        'x-slack-request-timestamp': timestamp
    }

    assert verify_slack_signature(headers, body, secret) is False


def test_verify_slack_signature_case_insensitive_headers():
    """Header lookup should be case-insensitive (API GW lowercases)."""
    from lambdas.slack_delivery.main import verify_slack_signature

    secret = "test_secret_32chars_exactly_here"
    timestamp = str(int(time.time()))
    body = "payload=%7B%22type%22%3A%22block_actions%22%7D"
    valid_sig = make_valid_signature(secret, timestamp, body)

    # Mixed case headers (as they might arrive before lowercasing)
    headers = {
        'X-Slack-Signature': valid_sig,
        'X-Slack-Request-Timestamp': timestamp
    }

    assert verify_slack_signature(headers, body, secret) is True


def test_verify_slack_signature_malformed_timestamp():
    """Non-integer timestamp should return False, not raise."""
    from lambdas.slack_delivery.main import verify_slack_signature

    secret = "test_secret_32chars_exactly_here"
    body = "payload=%7B%22type%22%3A%22block_actions%22%7D"

    headers = {
        'x-slack-signature': 'v0=anything',
        'x-slack-request-timestamp': 'not-a-number'
    }

    assert verify_slack_signature(headers, body, secret) is False
