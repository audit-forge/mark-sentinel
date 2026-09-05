"""Normalize CloudTrail S3 data events for Protected Cloud Assets.

This module is intentionally credential-free. A customer-controlled AWS
forwarder delivers CloudTrail events after authenticating to Arckon; Arckon
never receives AWS access keys and never retrieves object contents.
"""
from __future__ import annotations

import re
from typing import Any


_S3_EVENTS = {
    'GetObject': 'read', 'HeadObject': 'read', 'SelectObjectContent': 'read',
    'PutObject': 'write', 'CompleteMultipartUpload': 'write',
    'DeleteObject': 'delete', 'DeleteObjectVersion': 'delete',
    'CopyObject': 'write', 'RestoreObject': 'read',
}
_ACCOUNT_RE = re.compile(r'^\d{12}$')


def normalize_cloudtrail_s3_event(payload: dict[str, Any]) -> dict[str, str] | None:
    """Return safe S3 access metadata from one CloudTrail event, or None.

    Only S3 object data events are accepted. Object contents, request headers,
    source IP addresses, and arbitrary CloudTrail fields are deliberately not
    retained.
    """
    event = payload.get('detail', payload)
    if not isinstance(event, dict) or event.get('eventSource') != 's3.amazonaws.com':
        return None
    name = str(event.get('eventName', ''))
    action = _S3_EVENTS.get(name)
    params = event.get('requestParameters') or {}
    bucket = str(params.get('bucketName', '')).strip()
    key = str(params.get('key', '')).lstrip('/')
    if not action or not bucket or not key or '\x00' in bucket or '\x00' in key:
        return None
    account = str(event.get('recipientAccountId', '')).strip()
    if account and not _ACCOUNT_RE.fullmatch(account):
        return None
    identity = event.get('userIdentity') or {}
    actor = str(identity.get('arn') or identity.get('principalId') or 'unknown')[:512]
    region = str(event.get('awsRegion', '')).strip()[:64]
    return {
        'provider': 'aws', 'resource_type': 's3_object',
        'account_id': account, 'region': region,
        'resource': f's3://{bucket}/{key}', 'actor': actor,
        'action': action, 'event_name': name,
        'event_id': str(event.get('eventID', ''))[:256],
        # Tags are evaluated in-memory only and never persisted. They must be
        # supplied by the authenticated customer-owned forwarder after it has
        # resolved the object's tags with least-privilege AWS access.
        'resource_tags': event.get('arckonResourceTags', {}) if isinstance(
            event.get('arckonResourceTags', {}), dict) else {},
    }


def policy_matches_event(policy: dict[str, Any], event: dict[str, str]) -> bool:
    """Match an AWS S3 event to a constrained bucket/prefix policy.

    The policy scope is an s3://bucket or s3://bucket/prefix value. Wildcards
    are not supported to avoid accidental fleet-wide monitoring.
    """
    if policy.get('provider') != event.get('provider'):
        return False
    if policy.get('resource_type') != event.get('resource_type'):
        return False
    if policy.get('account_id') and policy['account_id'] != event.get('account_id'):
        return False
    if policy.get('tag_key'):
        if event.get('resource_tags', {}).get(policy['tag_key']) != policy.get('tag_value', ''):
            return False
    scope = str(policy.get('resource_scope', '')).rstrip('/')
    resource = str(event.get('resource', ''))
    return resource == scope or resource.startswith(scope + '/')
