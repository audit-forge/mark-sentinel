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
_AZURE_SUBSCRIPTION_RE = re.compile(r'/subscriptions/([^/]+)', re.IGNORECASE)


def normalize_cloudtrail_s3_event(payload: dict[str, Any]) -> dict[str, Any] | None:
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


def normalize_gcp_storage_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize one Cloud Audit Logs Cloud Storage object data-access event."""
    proto = payload.get('protoPayload', payload)
    if not isinstance(proto, dict) or proto.get('serviceName') != 'storage.googleapis.com':
        return None
    method = str(proto.get('methodName', ''))
    action = {
        'storage.objects.get': 'read', 'storage.objects.create': 'write',
        'storage.objects.update': 'write', 'storage.objects.delete': 'delete',
    }.get(method)
    resource_name = str(proto.get('resourceName', ''))
    marker = '/buckets/'
    if not action or marker not in resource_name or '/objects/' not in resource_name:
        return None
    bucket_and_key = resource_name.split(marker, 1)[1]
    bucket, key = bucket_and_key.split('/objects/', 1)
    if not bucket or not key or '\x00' in bucket or '\x00' in key:
        return None
    auth = proto.get('authenticationInfo') or {}
    labels = (payload.get('resource') or {}).get('labels') or {}
    return {
        'provider': 'gcp', 'resource_type': 'gcs_object',
        'account_id': str(labels.get('project_id', ''))[:256],
        'region': str(labels.get('location', ''))[:64],
        'resource': f'gs://{bucket}/{key.lstrip("/")}',
        'actor': str(auth.get('principalEmail') or 'unknown')[:512],
        'action': action, 'event_name': method,
        'event_id': str(payload.get('insertId', ''))[:256],
        'resource_tags': payload.get('arckonResourceLabels', {}) if isinstance(
            payload.get('arckonResourceLabels', {}), dict) else {},
    }


def normalize_azure_blob_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a customer-forwarded Azure Storage Blob diagnostic event.

    Azure Activity Log omits Blob data-plane reads. The customer forwarder must
    source StorageRead/StorageWrite/StorageDelete diagnostic records and send
    their URI, operation name, caller identity, and correlation ID.
    """
    record = payload.get('data', payload)
    if not isinstance(record, dict):
        return None
    operation = str(record.get('operationName') or record.get('operation') or '')
    lower = operation.lower()
    action = 'read' if any(v in lower for v in ('getblob', 'read', 'headblob')) else \
        'write' if any(v in lower for v in ('putblob', 'write', 'appendblob')) else \
        'delete' if 'deleteblob' in lower or 'delete' in lower else None
    uri = str(record.get('resourceUri') or record.get('uri') or '')
    match = re.match(r'https://([a-z0-9-]+)\.blob\.core\.windows\.net/([^/]+)/(.*)', uri, re.I)
    if not action or not match or not match.group(3) or '\x00' in uri:
        return None
    resource_id = str(record.get('resourceId') or '')
    subscription = _AZURE_SUBSCRIPTION_RE.search(resource_id)
    return {
        'provider': 'azure', 'resource_type': 'azure_blob',
        'account_id': subscription.group(1) if subscription else '',
        'region': str(record.get('location', ''))[:64],
        'resource': f'azure://{match.group(1)}/{match.group(2)}/{match.group(3)}',
        'actor': str(record.get('identity') or record.get('caller') or 'unknown')[:512],
        'action': action, 'event_name': operation[:256],
        'event_id': str(record.get('correlationId') or record.get('eventId') or '')[:256],
        'resource_tags': record.get('arckonResourceTags', {}) if isinstance(
            record.get('arckonResourceTags', {}), dict) else {},
    }


def normalize_cloud_asset_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return a supported normalized cloud event without retaining raw input."""
    return (normalize_cloudtrail_s3_event(payload)
            or normalize_gcp_storage_event(payload)
            or normalize_azure_blob_event(payload))


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
