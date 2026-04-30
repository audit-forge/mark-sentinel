Sample PDF Report generator

This project includes a simple script to generate a PDF from the compliance markdown output.

Usage (quick):
1) Produce compliance markdown: python3 audit.py --mode config --profile smb --target test/fixtures/deploy-hardened --output compliance --out-file output/artifacts/hardened_run
2) Convert to PDF (requires pandoc + wkhtmltopdf or similar):
   pandoc output/artifacts/hardened_run.md -o output/artifacts/hardened_run.pdf

Notes:
- We provide a simple template in docs/report_template.html for branding and layout.
- For automated report generation, consider adding a small script that runs audit and converts to PDF; this can be invoked by the one-command installer as an optional step.
