# V1 Release Boundary

This document defines the acceptance criteria for M.A.R.K. Sentinel v1.0
(pilot-ready). All items must be complete and evidence provided before a pilot
release is approved.

Acceptance criteria
- All baseline checks implemented and documented (31/32 checks as defined in the benchmark).
- Config mode and API/local modes implemented and validated against fixtures.
- Plain English and SARIF outputs available and validated.
- Compliance formatter produces framework-mapped documents from findings (SARIF -> compliance doc).
- Docker and kubectl connectors implemented and unit-tested against fixtures.
- FedRAMP and CMMC profiles created and validated against fixtures.
- `docs/PILOT_TESTER_HANDOFF.md` and this `V1_RELEASE_BOUNDARY.md` are present in docs/.

Evidence required
- Passing unit & integration test suite (attach pytest output).
- Example SARIF and compliance report artifacts from a run against the hardened fixtures.
- A short pilot-run checklist and list of known limitations.

Known limitations (to be documented in pilot handoff)
- Live Anthropic validation deferred until API access is restored (May 1). The code path supports any OpenAI-compatible endpoint and Ollama.
- Live kubectl cluster validation requires kubeconfig/cluster access and is not performed by default on fixtures.

Done boundary
- When the above acceptance criteria are met and evidence is attached to the release candidate, v1.0 is considered pilot-ready.
