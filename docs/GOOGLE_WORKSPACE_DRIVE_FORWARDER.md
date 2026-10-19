# Google Workspace Drive Audit Forwarding

This guide enables Arckon Protected Cloud Asset alerts for Google Docs, Sheets,
Slides, and Drive files. The customer runs the forwarder in their own Google
Cloud project or managed environment. Arckon receives only authenticated audit
metadata; it does not receive the Google service-account key or file contents.

## Before you begin

You need:

- A Google Workspace Super Admin to authorize domain-wide delegation.
- A Google Cloud project owned by the customer.
- An account in that project that can create a service account and key, or an
  alternative customer-managed workload identity implementation.
- A protected Drive document policy in Arckon.
- A host or scheduled job in the customer environment that can reach Google
  APIs and the customer's Arckon dashboard URL over HTTPS.

The bundled script polls the Google Workspace Admin SDK Reports API every 30
seconds. It is not a prevention control. Google publishes Drive audit records
asynchronously — Google's official documentation ("Data retention and lag
times", https://support.google.com/a/answer/7061566) states Drive log events
are typically available in "near real time (a couple of minutes)" after the
action occurs. Google also notes: "There's a small chance that reports and
log event data for some events will be delayed beyond the specified times.
In rare cases, events might not be reported." A 30-second poll reduces
Arckon's wait after publication; it does not make Google audit publication
instant or predictable. Drive log event data is retained for 6 months.

## 1. Create the Arckon policy

1. In Arckon, open **Protected Cloud Assets** and select **Add Cloud Policy**.
2. Select **Google Workspace Drive**.
3. For one document, copy the ID between `/d/` and the next `/` in the Drive
   URL. For example, `https://docs.google.com/document/d/1aB2cD3e/edit` becomes
   `gworkspace://1aB2cD3e`.
4. Enter the Workspace domain in the **Workspace domain** field.
5. Leave **AI only** off unless only automated identities should generate an
   alert, then save the policy.
6. Select **Show Cloud Ingest Token** and store the displayed token in the
   customer's secret manager or a root-owned local file. Treat it as a password.

Do not use the full Drive URL, a bare document ID, or a wildcard as the scope.
The policy should exist before testing so the first forwarded matching activity
creates an event and alert.

## 2. Configure Google Cloud

Perform these steps in a Google Cloud project controlled by the customer.

1. Enable the **Admin SDK API** for the project.
2. Create a dedicated service account, for example
   `arckon-drive-audit-forwarder`.
3. In the service account's advanced settings, enable **Domain-wide delegation**.
4. Copy the service account's numeric OAuth **Client ID** from its advanced
   settings. This is not the service-account email address.
5. Create a JSON key only when the bundled script runs outside Google Cloud
   with workload identity. Keep the key in the customer's secret manager or in
   a root-owned file with mode `0600`. Do not upload it to Arckon.

## 3. Authorize Google Workspace access

This step must be performed by a Google Workspace Super Admin.

1. Open Google Admin Console: **Security** > **Access and data control** >
   **API controls** > **Manage Domain Wide Delegation**.
2. Select **Add new**.
3. Enter the service account's numeric OAuth Client ID.
4. Authorize only this scope:

   ```text
   https://www.googleapis.com/auth/admin.reports.audit.readonly
   ```

5. Save the authorization and verify the scope appears on the client record.
6. Choose an existing Workspace administrator as the delegated
   `--admin-email`; that account must be permitted to read Drive audit reports.

Domain-wide delegation can take time to propagate. Do not add the broader
Google Drive read/write scope: the forwarder needs only audit-report read access.

## 4. Install and run the forwarder

Copy `scripts/gworkspace_drive_forwarder.py` from the Arckon release to the
customer-managed scheduler host. Install its dependencies in an isolated Python
environment:

```sh
python3 -m venv /opt/arckon-drive-forwarder/venv
/opt/arckon-drive-forwarder/venv/bin/pip install google-api-python-client google-auth google-auth-httplib2
```

Store the service-account key and Arckon ingest token outside the application
directory, readable only by the service account that runs the job:

```sh
install -d -m 700 /etc/arckon-drive-forwarder
install -m 600 service-account.json /etc/arckon-drive-forwarder/service-account.json
install -m 600 arckon-ingest-token /etc/arckon-drive-forwarder/arckon-ingest-token
```

Run a manual poll before scheduling it. Substitute the customer values:

```sh
/opt/arckon-drive-forwarder/venv/bin/python gworkspace_drive_forwarder.py \
  --service-account-key /etc/arckon-drive-forwarder/service-account.json \
  --admin-email workspace-admin@example.com \
  --arckon-url https://customer.arckon.example \
  --arckon-token-file /etc/arckon-drive-forwarder/arckon-ingest-token \
  --domain example.com \
  --state-file /var/lib/arckon-drive-forwarder/state
```

The token-file option prevents the ingest token from appearing in the process
list. The `--state-file` location stores the last successful timestamp; keep
it persistent and writable by the scheduled-job account.

Schedule the same command every 30 seconds. Run it under a dedicated non-login
service account and redirect output to a protected log. Do not overlap runs;
use a systemd timer, a scheduler with concurrency one, or a lock if a poll can
take longer than the schedule interval.

For Arckon GCP deployments, use the included
`deploy/gcp/arckon-gworkspace-drive-forwarder@.service` and `.timer` templates.
They run the forwarder in a constrained Docker container on the tenant's
private Docker network. Create `/etc/arckon-drive-forwarder/CUSTOMER_ID.env`
with these non-secret values before enabling the timer:

```text
ADMIN_EMAIL=workspace-admin@example.com
WORKSPACE_DOMAIN=example.com
```

## 5. Verify alerts end to end

1. Wait for the authorization and forwarder to be active.
2. Access the protected document with a Workspace account.
3. Wait for Google audit-log availability and the next forwarder poll. Google
   controls audit publication timing, so this is variable and not instant.
4. In Arckon, open **Protected Cloud Assets** and confirm an event appears.
5. Confirm the CRITICAL `PROTECTED-CLOUD-ASSET-ACCESS` alert arrives through
   the enabled notification channel.

If an event appears but no notification arrives, use Arckon **Settings** to
send a test alert and verify the protected-cloud-asset trigger is enabled. If
no event appears, troubleshoot the forwarder first.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `403` or delegation error from Google | Confirm the numeric service-account Client ID, not its email, is authorized in Domain Wide Delegation with the exact audit-read scope. Confirm propagation has completed. |
| No forwarded activities | Confirm Admin SDK API is enabled, `--admin-email` is a valid delegated administrator, and the forwarder can write its state file. |
| Forwarder reports HTTP `401` | Retrieve the per-customer Cloud Ingest Token again and replace the token file. Do not use another tenant's token. |
| Forwarder reports HTTP `200` but `stored: 0` | Check the document ID, the Workspace domain on the policy, and whether the Drive action is one Arckon supports. |
| Event is visible but no notification | Confirm the `protected_cloud_asset_access` alert trigger and at least one notification channel are enabled. |
| Folder policy does not alert | The bundled forwarder sends individual document IDs. Folder policies require a customer-managed enrichment step that supplies `arckonResourcePath`. |

## Security and ownership

- The customer owns the Google Cloud project, service account, service-account
  key or workload identity, Workspace authorization, scheduler, and credential
  rotation.
- Arckon stores policy metadata and normalized access-event metadata, not file
  contents or raw Google audit payloads.
- Review the delegated client and scope periodically in Google Admin Console.
  Remove the domain-wide delegation entry and revoke the service account when
  the integration is retired.

## Google references

- [Control API access with domain-wide delegation](https://support.google.com/a/answer/162106)
- [Reports API: Drive Activity Report](https://developers.google.com/admin-sdk/reports/v1/guides/manage-audit-drive)
