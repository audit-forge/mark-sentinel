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

# Heuristics for detecting AI/automated (non-human) actors in cloud audit
# events. These are intentionally conservative — when unclear, we classify
# as 'human' to avoid missing alerts for AI tools that impersonate users.
_AI_ACTOR_PATTERNS = re.compile(
    r'(?:'
    r'assumed-role/[^/]*(?:ai|agent|bot|claude|copilot|cursor|llm|model|'
    r'inference|gpt|gemini|bedrock|sagemaker|vertex|pipeline|automation)'
    r'|service-account@'
    r'|@[a-z0-9-]+\.iam\.gserviceaccount\.com'
    r'|system:serviceaccount:'
    r'|machine-identity'
    r'|workload-identity'
    r'|ai[-_]?(?:agent|bot|worker|runner|service|tool)[@:]'
    r'|(?:agent|bot|automation)[@:]'
    r')',
    re.IGNORECASE,
)


def detect_actor_type(actor: str) -> str:
    """Classify an actor identity as 'ai' or 'human'.

    Uses pattern matching on service-account ARNs, IAM emails, and
    known AI-tool naming patterns. Returns 'ai' if the actor looks
    like an automated/AI identity, 'human' otherwise.

    This is heuristic — a human using an AI tool that runs under a
    service account will appear as 'ai', which is the desired behavior
    for AI-only alerting (the access was performed by the AI tool, not
    by the human directly).
    """
    if not actor:
        return 'human'
    return 'ai' if _AI_ACTOR_PATTERNS.search(actor) else 'human'


def normalize_cloudtrail_s3_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return safe S3 access metadata from one CloudTrail event, or None.

    Only S3 object data events are accepted. Object contents, request headers,
    and arbitrary CloudTrail fields are deliberately not retained. Source IP
    and device name (if supplied by the forwarder) are included for alerting.
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
    source_ip = str(event.get('sourceIPAddress', ''))[:64]
    device_name = str(payload.get('arckonDeviceName', event.get('arckonDeviceName', '')))[:128]
    return {
        'provider': 'aws', 'resource_type': 's3_object',
        'account_id': account, 'region': region,
        'resource': f's3://{bucket}/{key}', 'actor': actor,
        'actor_type': detect_actor_type(actor),
        'action': action, 'event_name': name,
        'event_id': str(event.get('eventID', ''))[:256],
        'source_ip': source_ip, 'device_name': device_name,
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
    req_meta = proto.get('requestMetadata') or {}
    source_ip = str(req_meta.get('callerIp', ''))[:64]
    device_name = str(payload.get('arckonDeviceName', ''))[:128]
    return {
        'provider': 'gcp', 'resource_type': 'gcs_object',
        'account_id': str(labels.get('project_id', ''))[:256],
        'region': str(labels.get('location', ''))[:64],
        'resource': f'gs://{bucket}/{key.lstrip("/")}',
        'actor': str(auth.get('principalEmail') or 'unknown')[:512],
        'actor_type': detect_actor_type(str(auth.get('principalEmail') or 'unknown')),
        'action': action, 'event_name': method,
        'event_id': str(payload.get('insertId', ''))[:256],
        'source_ip': source_ip, 'device_name': device_name,
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
    source_ip = str(record.get('callerIpAddress', ''))[:64]
    device_name = str(payload.get('arckonDeviceName', record.get('arckonDeviceName', '')))[:128]
    return {
        'provider': 'azure', 'resource_type': 'azure_blob',
        'account_id': subscription.group(1) if subscription else '',
        'region': str(record.get('location', ''))[:64],
        'resource': f'azure://{match.group(1)}/{match.group(2)}/{match.group(3)}',
        'actor': str(record.get('identity') or record.get('caller') or 'unknown')[:512],
        'actor_type': detect_actor_type(str(record.get('identity') or record.get('caller') or '')),
        'action': action, 'event_name': operation[:256],
        'event_id': str(record.get('correlationId') or record.get('eventId') or '')[:256],
        'source_ip': source_ip, 'device_name': device_name,
        'resource_tags': record.get('arckonResourceTags', {}) if isinstance(
            record.get('arckonResourceTags', {}), dict) else {},
    }


def normalize_google_workspace_drive_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Normalize a Google Workspace Drive audit activity from the Admin SDK
    Reports API (applicationName=drive).

    A customer-controlled forwarder polls the Reports API with a service
    account that has domain-wide delegation for
    ``https://www.googleapis.com/auth/admin.reports.audit.readonly`` and
    forwards each activity to Arckon. Arckon never receives the service
    account credentials or file contents — only the audit metadata.

    The forwarder supplies the Drive file URL (``gworkspace://<doc_id>``)
    and, optionally, a ``resource_path`` (folder path) so policies can
    match by folder prefix.
    """
    activity = payload.get('events', [payload]) if isinstance(
        payload.get('events'), list) else [payload]
    if not activity:
        return None
    event = activity[0] if isinstance(activity[0], dict) else {}
    # The Reports API wraps each activity in id/time/actor/events; accept
    # both the wrapped and unwrapped shapes.
    inner = event.get('events', [event])
    inner = inner[0] if isinstance(inner, list) and inner and isinstance(inner[0], dict) else event
    name = str(inner.get('name', ''))
    if not name:
        return None
    # Map Drive audit event names to canonical actions
    action = (
        'read' if name in ('view', 'download', 'preview') else
        'write' if name in ('edit', 'create', 'upload', 'rename', 'move',
                            'add_to_folder', 'change_document_visibility',
                            'share', 'change_user_access') else
        'delete' if name in ('delete', 'trash', 'untrash') else None
    )
    if not action:
        return None
    params = inner.get('parameters') or []
    # Reports API returns parameters as a list of {name, value} dicts
    fields: dict[str, Any] = {}
    if isinstance(params, list):
        for p in params:
            if isinstance(p, dict) and 'name' in p:
                fields[p['name']] = p.get('value') or p.get('multiValue') or ''
    elif isinstance(params, dict):
        fields = params
    doc_id = str(fields.get('doc_id', '')).strip()
    doc_title = str(fields.get('doc_title', '')).strip()
    if not doc_id or '\x00' in doc_id:
        return None
    # Actor is at the top level of the activity, not inside the inner event
    top_actor = payload.get('actor', {}) if isinstance(payload, dict) else {}
    actor_email = str(top_actor.get('email', ''))[:512] if isinstance(top_actor, dict) else ''
    if not actor_email:
        actor_email = str(fields.get('actor', 'unknown'))[:512]
    # The forwarder may supply a folder path for prefix-based policies
    resource_path = str(payload.get('arckonResourcePath', fields.get('resource_path', ''))).strip()
    resource = f'gworkspace://{doc_id}'
    if resource_path:
        resource = f'gworkspace://{resource_path.rstrip("/")}/{doc_title or doc_id}'
    domain = str(payload.get('arckonDomain', ''))[:128]
    # Event ID: use arckonEventId if supplied, else the Reports API id.time
    event_id = str(payload.get('arckonEventId', '')).strip()
    if not event_id:
        top_id = payload.get('id', {})
        if isinstance(top_id, dict):
            event_id = str(top_id.get('time', ''))
        else:
            event_id = str(top_id)
    # Device name: the forwarder can enrich events with the device hostname
    # (e.g., by correlating the source IP with the endpoint inventory).
    device_name = str(payload.get('arckonDeviceName', ''))[:128]
    return {
        'provider': 'gworkspace', 'resource_type': 'drive_file',
        'account_id': domain, 'region': '',
        'resource': resource, 'actor': actor_email,
        'actor_type': detect_actor_type(actor_email),
        'action': action, 'event_name': name,
        'event_id': event_id[:256],
        'source_ip': '', 'device_name': device_name,
        'resource_tags': payload.get('arckonResourceTags', {}) if isinstance(
            payload.get('arckonResourceTags', {}), dict) else {},
        'doc_title': doc_title[:256],
    }


def normalize_cloud_asset_event(payload: dict[str, Any]) -> dict[str, Any] | None:
    """Return a supported normalized cloud event without retaining raw input."""
    return (normalize_cloudtrail_s3_event(payload)
            or normalize_gcp_storage_event(payload)
            or normalize_azure_blob_event(payload)
            or normalize_google_workspace_drive_event(payload))


def policy_matches_event(policy: dict[str, Any], event: dict[str, str]) -> bool:
    """Match a normalized cloud event to a constrained scope policy.

    The policy scope is a provider-specific URI (s3://, gs://, azure://,
    or gworkspace://). Wildcards are not supported to avoid accidental
    fleet-wide monitoring.
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
