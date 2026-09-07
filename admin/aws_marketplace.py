"""AWS Marketplace SaaS fulfillment primitives for Arckon.

Uses AWS SDK's default credential chain so credentials remain in the workload
role/identity provider. Never accept AWS access keys from a marketplace buyer.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any


def resolve_customer(registration_token: str) -> dict[str, str]:
    """Resolve one short-lived AWS Marketplace registration token.

    The configured product code is allowlisted to prevent a token for another
    seller product from provisioning an Arckon tenant.
    """
    if not registration_token or len(registration_token) > 4096:
        raise ValueError('invalid Marketplace registration token')
    product_code = os.environ.get('AWS_MARKETPLACE_PRODUCT_CODE', '').strip()
    if not product_code:
        raise RuntimeError('AWS_MARKETPLACE_PRODUCT_CODE is not configured')
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise RuntimeError('boto3 is required for AWS Marketplace fulfillment') from exc
    client = boto3.client('meteringmarketplace', region_name='us-east-1', config=Config(
        retries={'total_max_attempts': 3, 'mode': 'adaptive'},
        connect_timeout=5, read_timeout=15,
    ))
    response: dict[str, Any] = client.resolve_customer(RegistrationToken=registration_token)
    if response.get('ProductCode') != product_code:
        raise ValueError('Marketplace product code did not match the configured Arckon offer')
    customer_id = str(response.get('CustomerIdentifier', ''))
    account_id = str(response.get('CustomerAWSAccountId', ''))
    if not customer_id or not account_id:
        raise ValueError('Marketplace did not return a customer identity')
    return {'customer_id': customer_id, 'account_id': account_id, 'product_code': product_code}


def get_entitlement(customer_id: str, product_code: str) -> dict[str, Any]:
    """Return active AWS Marketplace SaaS entitlements for one buyer."""
    try:
        import boto3
        from botocore.config import Config
    except ImportError as exc:
        raise RuntimeError('boto3 is required for AWS Marketplace entitlements') from exc
    client = boto3.client('marketplace-entitlement-service', region_name='us-east-1', config=Config(
        retries={'total_max_attempts': 3, 'mode': 'adaptive'},
        connect_timeout=5, read_timeout=15,
    ))
    paginator = client.get_paginator('get_entitlements')
    entitlements = []
    for page in paginator.paginate(ProductCode=product_code, Filter={'CUSTOMER_IDENTIFIER': [customer_id]}):
        entitlements.extend(page.get('Entitlements', []))
    active = []
    now = datetime.now(timezone.utc)
    for entitlement in entitlements:
        expiry = entitlement.get('ExpirationDate')
        # AWS returns a timezone-aware datetime. An absent expiration is an
        # active perpetual entitlement; an expired one must never grant access.
        if expiry is None or expiry > now:
            active.append(entitlement)
    return {'active': bool(active), 'entitlements': active}
