# AI Data Retention Policy

## Scope
Covers AI prompts, responses, logs, embeddings, and any related datasets.

## Retention windows
- Prompts/responses: 30 days unless a longer period is required for support or compliance
- Operational logs: 90 days
- Embeddings / derived vector data: 90 days unless business need requires shorter retention
- Test fixtures and synthetic data: retain only while needed for development/testing

## Storage locations
- Application logs
- Provider-side storage (if enabled)
- Local or hosted vector stores

## Deletion process
- Delete records on request where applicable
- Remove expired logs via rotation / retention policy
- Review provider retention settings quarterly
