# AWS Marketplace SaaS Technical Setup

Arckon uses the AWS Marketplace SaaS fulfillment flow. Buyers subscribe in
AWS Marketplace, are redirected to `/marketplace/aws/fulfillment`, and Arckon
resolves the short-lived registration token server-side.

## Required seller configuration

Set `AWS_MARKETPLACE_PRODUCT_CODE` to the exact product code assigned to the
Arckon AWS Marketplace offer. Do not accept a product code from the browser.

Run the Arckon admin service with an IAM role, not access keys. The role needs
only:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Effect":"Allow","Action":"aws-marketplace:ResolveCustomer","Resource":"*"},
    {"Effect":"Allow","Action":"aws-marketplace:GetEntitlements","Resource":"*"}
  ]
}
```

Use a workload identity or equivalent role delivery. Never put AWS keys in an
Arckon customer record, dashboard form, or agent configuration.

## Fulfillment flow

1. Configure the Marketplace fulfillment URL as
   `https://admin.riskraven.ai/marketplace/aws/fulfillment`.
2. AWS redirects a subscribed buyer with `x-amzn-marketplace-token`.
3. Arckon calls `ResolveCustomer` and verifies the returned product code against
   `AWS_MARKETPLACE_PRODUCT_CODE`.
4. Arckon creates a 15-minute, one-use fulfillment session. The raw AWS token
   is never persisted.
5. An Arckon super-admin binds the verified buyer to an existing isolated tenant.
6. Entitlement synchronization sets the tenant to `active` or suspends it while
   preserving its data, dashboard, and configuration.

## Before publishing

- Configure SaaS contract dimensions (for example Standard and Pro endpoint
  seats) in the Marketplace offer.
- Map each Marketplace dimension to Arckon tier/feature flags.
- Add recurring entitlement synchronization and buyer lifecycle handling.
- Validate subscription, entitlement, cancellation, and reinstatement flows in
  AWS Marketplace staging before submitting the listing.
