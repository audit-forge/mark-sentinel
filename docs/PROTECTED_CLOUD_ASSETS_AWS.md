# Protected Cloud Assets: AWS, Azure, and GCP

Protected Cloud Assets monitors AWS CloudTrail S3 **data events** for explicit
S3 bucket or prefix policies. It sends a CRITICAL alert when an authenticated
CloudTrail forwarder reports access to a matching asset.

## What Arckon stores

- S3 URI, AWS account ID, region, CloudTrail event ID, action, and actor ARN.
- No object contents, request body, request headers, source IP, or raw
  CloudTrail payload.
- A SHA-256 hash chain makes stored events tamper-evident.

## Safe deployment model

1. Enable CloudTrail S3 data events only for the buckets/prefixes you need.
2. Deploy a customer-owned forwarder (for example Lambda subscribed to the
   CloudTrail/EventBridge stream) in the customer's AWS account.
3. Give that forwarder least privilege: CloudTrail read/receive permission and,
   only when tag matching is configured, `s3:GetObjectTagging` for the explicit
   protected scope. It must not receive `s3:GetObject`.
4. Retrieve the dedicated per-customer ingest token from the Protected Cloud
   Assets integration setup. Arckon creates it in the customer data volume
   with mode `0600`; it is not an environment variable. Do not use an
   endpoint-agent token or an AWS access key. The forwarder sends it as
   `Authorization: Bearer <token>` to `POST /api/cloud-assets/events` over
   HTTPS.
5. The forwarder sends one CloudTrail event per request. For tag-enforced
   policies, it may add `detail.arckonResourceTags` after looking up tags. Tags
   are evaluated in memory and are never persisted by Arckon.

## Policies

Policies are intentionally narrow:

- Provider: AWS
- Resource: S3 object
- Scope: an explicit `s3://bucket` or `s3://bucket/prefix`
- AWS account ID: optional 12-digit account restriction
- Required tag: optional exact key/value such as `Criticality=Critical`

Wildcards are rejected. A tag is an additional constraint, not a replacement
for an explicit scope. This avoids accidentally monitoring an entire AWS
estate because a generic tag name was reused.

## Forwarder event shape

Send the CloudTrail event itself, or an EventBridge envelope with the event in
`detail`. Arckon accepts only S3 object operations: GetObject, HeadObject,
SelectObjectContent, PutObject, CompleteMultipartUpload, DeleteObject,
DeleteObjectVersion, CopyObject, and RestoreObject. CloudTrail `eventID` is
required and makes retries idempotent.

## Azure Blob Storage

Configure an explicit `azure://storage-account/container/prefix` scope and,
optionally, an exact Azure resource tag. Forward Azure Storage diagnostic
records from `StorageRead`, `StorageWrite`, and `StorageDelete`; Azure Activity
Log alone is insufficient because it does not record Blob data-plane reads.
The forwarder supplies the Blob URI, operation, identity, correlation ID, and
optionally `arckonResourceTags` after looking up tags with least privilege.

## GCP Cloud Storage

Configure an explicit `gs://bucket/prefix` scope and, optionally, an exact GCP
resource label. Forward Cloud Audit Logs Data Access entries for
`storage.objects.get`, `create`, `update`, and `delete`. A forwarder may add
`arckonResourceLabels` after resolving bucket labels. Grant it only the log
subscription role and, when label matching is used, read-only metadata access
to the configured buckets; it must not receive object-read permissions.

## Limitations

- Tag/label matching depends on the customer-controlled forwarder accurately looking
  up the object tags. Arckon does not treat a caller-supplied "critical" field
  as evidence without a matching explicit scope and authenticated transport.
