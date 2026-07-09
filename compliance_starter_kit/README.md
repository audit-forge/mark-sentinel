# Arckon Compliance Starter Kit

To remediate the EU AI Act governance and runtime findings for a device:

1. Copy this whole `compliance_starter_kit` folder into the directory Arckon scans
   on that device (your **home directory** by default), and rename it to **`compliance`**.
       cp -r compliance_starter_kit ~/compliance
2. Open each file and replace every **[PLACEHOLDER]** with your real values.
3. For `ai_runtime_config.json`: only set a flag to `true` / a real number if your
   system ACTUALLY has that control. If it doesn't, implement the control first.
4. Re-run the Arckon scan. The governance checks (AI-GOV-001/002/003/005) and any
   runtime checks whose controls you declared will move to PASS.

Standard filenames Arckon recognises (keep these names):
  ai_usage_policy.md  data_retention_policy.md  ai_incident_response_plan.md
  ai_asset_inventory.md  ai_runtime_config.json
