Phase 4 — SMB Polish & Packaging (draft release notes)

Summary
- One-command installer (scripts/install.sh) for SMB users
- SMB Quickstart and Sample PDF report generator (scripts/generate_pdf.sh and scripts/md_to_pdf.py)
- README updated with SMB Quickstart and Enterprise/Developer sections
- CI smoke tests added to validate installer and core tests on PRs
- Docker build and PyPI publish workflows scaffolded (publish gated on secrets)

Artifacts
- PDF report: output/artifacts/hardened_run.pdf (SHA256: d3066b1f710a7ca3a6bde1e4ae32734f7f80beea67865229c338c8ea359d5043)

Notes for reviewers
- The Docker publish and PyPI publish workflows are intentionally gated; provide DOCKERHUB_TOKEN / PYPI_API_TOKEN as repo secrets to enable publishing.
- The PDF generator uses ReportLab as a fallback; if higher-fidelity rendering is required, install wkhtmltopdf or a TeX engine.

Signed,
Hash (assistant)
