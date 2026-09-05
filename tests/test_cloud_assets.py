from connectors.cloud_assets import normalize_cloudtrail_s3_event, policy_matches_event
from pathlib import Path
import tempfile

from storage import AgentStore


def _event(**overrides):
    event = {
        'eventSource': 's3.amazonaws.com', 'eventName': 'GetObject',
        'recipientAccountId': '123456789012', 'awsRegion': 'us-east-1',
        'eventID': 'evt-1',
        'requestParameters': {'bucketName': 'records', 'key': 'payroll/2026.csv'},
        'userIdentity': {'arn': 'arn:aws:sts::123456789012:assumed-role/ai/worker'},
    }
    event.update(overrides)
    return event


def test_normalizes_s3_object_metadata_without_contents():
    normalized = normalize_cloudtrail_s3_event(_event())
    assert normalized == {
        'provider': 'aws', 'resource_type': 's3_object',
        'account_id': '123456789012', 'region': 'us-east-1',
        'resource': 's3://records/payroll/2026.csv',
        'actor': 'arn:aws:sts::123456789012:assumed-role/ai/worker',
        'action': 'read', 'event_name': 'GetObject', 'event_id': 'evt-1',
        'resource_tags': {},
    }


def test_rejects_non_s3_unknown_actions_and_invalid_accounts():
    assert normalize_cloudtrail_s3_event(_event(eventSource='ec2.amazonaws.com')) is None
    assert normalize_cloudtrail_s3_event(_event(eventName='ListBuckets')) is None
    assert normalize_cloudtrail_s3_event(_event(recipientAccountId='not-an-account')) is None


def test_policy_requires_exact_bucket_prefix_scope():
    event = normalize_cloudtrail_s3_event(_event())
    policy = {'provider': 'aws', 'resource_type': 's3_object',
              'account_id': '123456789012', 'resource_scope': 's3://records/payroll'}
    assert policy_matches_event(policy, event)
    assert not policy_matches_event({**policy, 'resource_scope': 's3://records/pay'}, event)
    assert not policy_matches_event({**policy, 'account_id': '999999999999'}, event)


def test_cloud_policy_audit_and_event_idempotency():
    with tempfile.TemporaryDirectory() as tmp:
        store = AgentStore(Path(tmp) / 'agents.db')
        policy_id = store.add_protected_cloud_asset(
            'aws', 's3_object', '123456789012', 's3://records/payroll',
            'Criticality', 'Critical', 'test@example.com')
        policies = store.get_protected_cloud_assets()
        assert policies[0]['id'] == policy_id
        assert policies[0]['tag_key'] == 'Criticality'
        assert store.get_protected_cloud_assets_audit_log()[0]['action'] == 'upsert'
        event = normalize_cloudtrail_s3_event(_event(arckonResourceTags={'Criticality': 'Critical'}))
        assert policy_matches_event(policies[0], event)
        assert store.ingest_protected_cloud_event(event, policy_id)
        assert not store.ingest_protected_cloud_event(event, policy_id)
        stored = store.get_protected_cloud_events()
        assert stored[0]['resource'] == 's3://records/payroll/2026.csv'
        assert store.verify_protected_cloud_event_chain()
        assert store.remove_protected_cloud_asset(policy_id, 'test@example.com')
