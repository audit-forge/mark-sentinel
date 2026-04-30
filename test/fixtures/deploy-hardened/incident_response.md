# AI Incident Response Plan

## What counts as an AI incident
- Secret or sensitive data leakage
- Prompt injection causing unsafe behavior
- Model hallucination causing operational or customer harm
- Unauthorized model / plugin / agent deployment

## First response steps
1. Stop or isolate the affected AI service
2. Preserve logs and relevant evidence
3. Rotate any exposed credentials immediately
4. Notify the owner / response contacts

## Kill switch
- Disable the Hash-AI process, container, or endpoint
- Revoke external API credentials if compromise is suspected

## Evidence preservation
- Export logs before cleanup
- Save request / response samples and timestamps
- Preserve deployment/config state used during the incident

## Notification
- Notify internal owner first
- Notify external provider/security contact if applicable
- Assess legal/regulatory notice requirements if sensitive data was involved
