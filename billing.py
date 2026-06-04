"""
M.A.R.K. Sentinel — Billing scaffold (Stripe)

Wires Stripe Checkout into the self-serve signup flow.
Set env vars to activate; absent vars = billing disabled (admin-provisioned path).

Required env vars:
  STRIPE_SECRET_KEY        — sk_live_... or sk_test_...
  STRIPE_WEBHOOK_SECRET    — whsec_...  (from Stripe dashboard → Webhooks)
  STRIPE_PRICE_ID_STANDARD — price_...  (monthly, standard tier)
  STRIPE_PRICE_ID_PLUS     — price_...  (monthly, plus tier)

Optional:
  STRIPE_PORTAL_RETURN_URL — URL to redirect after customer portal session

Flow:
  1. POST /billing/checkout  → create Stripe Checkout session → redirect to Stripe
  2. Stripe redirects to /billing/success?session_id=... after payment
  3. Stripe sends webhook to /billing/webhook on subscription events
  4. Webhook handler provisions / updates / cancels the customer

Tiers map to license plan field:
  standard → 'standard'
  plus     → 'plus'
"""
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Optional

log = logging.getLogger('sentinel.billing')

_STRIPE_API = 'https://api.stripe.com/v1'

STRIPE_ENABLED = bool(os.environ.get('STRIPE_SECRET_KEY'))

_PRICE_MAP = {
    'standard': os.environ.get('STRIPE_PRICE_ID_STANDARD', ''),
    'plus':     os.environ.get('STRIPE_PRICE_ID_PLUS', ''),
}


# ── Stripe API helpers (no SDK — stdlib only) ─────────────────────────────────

def _stripe_post(path: str, data: dict) -> dict:
    secret = os.environ.get('STRIPE_SECRET_KEY', '')
    if not secret:
        raise RuntimeError('STRIPE_SECRET_KEY not set')
    encoded = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(
        f'{_STRIPE_API}{path}',
        data=encoded,
        headers={
            'Authorization': f'Bearer {secret}',
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        method='POST',
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        raise RuntimeError(f'Stripe API error {e.code}: {body}') from e


def _stripe_get(path: str) -> dict:
    secret = os.environ.get('STRIPE_SECRET_KEY', '')
    req = urllib.request.Request(
        f'{_STRIPE_API}{path}',
        headers={'Authorization': f'Bearer {secret}'},
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


# ── Checkout ──────────────────────────────────────────────────────────────────

def create_checkout_session(
    tier: str,
    customer_email: str,
    success_url: str,
    cancel_url: str,
    seats: int = 5,
    metadata: Optional[dict] = None,
) -> str:
    """Create a Stripe Checkout session and return the session URL."""
    if not STRIPE_ENABLED:
        raise RuntimeError('Stripe billing is not configured')
    price_id = _PRICE_MAP.get(tier)
    if not price_id:
        raise ValueError(f'No Stripe price configured for tier: {tier}')

    data = {
        'mode': 'subscription',
        'payment_method_types[]': 'card',
        'customer_email': customer_email,
        'line_items[0][price]': price_id,
        'line_items[0][quantity]': str(seats),
        'success_url': success_url,
        'cancel_url': cancel_url,
        'subscription_data[metadata][tier]': tier,
        'subscription_data[metadata][seats]': str(seats),
    }
    if metadata:
        for k, v in metadata.items():
            data[f'metadata[{k}]'] = str(v)

    session = _stripe_post('/checkout/sessions', data)
    log.info('Checkout session created: %s tier=%s seats=%d', session['id'], tier, seats)
    return session['url']


# ── Customer portal ───────────────────────────────────────────────────────────

def create_portal_session(stripe_customer_id: str, return_url: str) -> str:
    """Create a Stripe Customer Portal session so customers can manage their subscription."""
    if not STRIPE_ENABLED:
        raise RuntimeError('Stripe billing is not configured')
    session = _stripe_post('/billing_portal/sessions', {
        'customer': stripe_customer_id,
        'return_url': return_url,
    })
    return session['url']


# ── Webhook verification ──────────────────────────────────────────────────────

def verify_webhook(payload: bytes, sig_header: str) -> dict:
    """Verify Stripe webhook signature and return the parsed event."""
    secret = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    if not secret:
        raise RuntimeError('STRIPE_WEBHOOK_SECRET not set')

    parts = {p.split('=', 1)[0]: p.split('=', 1)[1]
             for p in sig_header.split(',') if '=' in p}
    timestamp = parts.get('t', '')
    v1_sig = parts.get('v1', '')

    signed = f'{timestamp}.'.encode() + payload
    expected = hmac.new(secret.encode(), signed, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(expected, v1_sig):
        raise ValueError('Webhook signature verification failed')

    age = abs(time.time() - int(timestamp))
    if age > 300:
        raise ValueError(f'Webhook timestamp too old ({age:.0f}s)')

    return json.loads(payload)


# ── Event handlers ────────────────────────────────────────────────────────────

def handle_webhook_event(event: dict, provision_fn, cancel_fn) -> str:
    """
    Dispatch a Stripe webhook event.

    provision_fn(customer_email, tier, seats, stripe_customer_id) — called on new/updated subscription
    cancel_fn(stripe_customer_id)                                  — called on cancellation

    Returns a status string for logging.
    """
    ev_type = event.get('type', '')
    obj = event.get('data', {}).get('object', {})

    if ev_type in ('checkout.session.completed',):
        mode = obj.get('mode')
        if mode != 'subscription':
            return f'skip: mode={mode}'
        email = obj.get('customer_email') or obj.get('customer_details', {}).get('email', '')
        sub_id = obj.get('subscription', '')
        customer_id = obj.get('customer', '')
        metadata = obj.get('metadata', {})
        tier = metadata.get('tier', 'standard')
        seats = int(metadata.get('seats', 5))
        log.info('checkout.session.completed: email=%s tier=%s seats=%d', email, tier, seats)
        provision_fn(email, tier, seats, customer_id)
        return 'provisioned'

    if ev_type in ('customer.subscription.updated',):
        metadata = obj.get('metadata', {})
        tier = metadata.get('tier', 'standard')
        seats = int(obj.get('quantity', 5))
        customer_id = obj.get('customer', '')
        log.info('subscription.updated: customer=%s tier=%s seats=%d', customer_id, tier, seats)
        provision_fn(None, tier, seats, customer_id)
        return 'updated'

    if ev_type in ('customer.subscription.deleted',):
        customer_id = obj.get('customer', '')
        log.info('subscription.deleted: customer=%s', customer_id)
        cancel_fn(customer_id)
        return 'cancelled'

    return f'unhandled: {ev_type}'
