from types import SimpleNamespace
import unittest

from aibom_generator import _extract_components
from audit import filter_results, inventory_results
from checks import CheckResult, PASS, WARN
from checks.supply_chain import check_supply_003
from output.json_report import format_json
import json


class SupplyChainRequirementsTests(unittest.TestCase):
    def test_pip_directives_are_not_counted_as_dependencies(self):
        ctx = SimpleNamespace(requirements_txt="""\
-e .
--index-url https://packages.example.invalid/simple
-r requirements-prod.txt
openai==1.68.2
""")

        result = check_supply_003(ctx)

        self.assertEqual(result.status, PASS)
        self.assertIn("All 1 packages", result.details)
        self.assertNotIn("-e", " ".join(result.evidence))

    def test_aibom_ignores_generic_packages_and_pip_directives(self):
        components = _extract_components([{
            "hostname": "Keiths-MacBook-Pro",
            "_report": {"findings": [{
                "check_id": "AI-SUPPLY-003",
                "status": "WARN",
                "title": "Dependencies",
                "details": "",
                "evidence": ["Unpinned packages: -e, requests"],
            }]},
        }])

        self.assertEqual(components["packages"], {})

    def test_aibom_keeps_real_unpinned_ai_packages(self):
        components = _extract_components([{
            "hostname": "Keiths-MacBook-Pro",
            "_report": {"findings": [{
                "check_id": "AI-SUPPLY-003",
                "status": "FAIL",
                "title": "Dependencies",
                "details": "",
                "evidence": ["Unpinned AI packages: -e, openai"],
            }]},
        }])

        self.assertEqual(list(components["packages"]), ["openai"])

    def test_inventory_survives_profile_filter_without_changing_findings(self):
        detected = CheckResult(
            check_id="AI-TOOL-006", title="Cursor IDE detected", status=WARN,
            severity="LOW", category="AI-TOOL", details="Cursor IDE is installed.",
        )
        profile = {"checks": ["AI-SUPPLY-003"], "severity_threshold": "MEDIUM"}

        self.assertEqual(filter_results([detected], profile), [])
        report = json.loads(format_json(
            [], profile, "/", "config", inventory_results=inventory_results([detected]),
        ))
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["inventory_findings"][0]["check_id"], "AI-TOOL-006")

    def test_aibom_reads_tool_details_from_inventory_findings(self):
        components = _extract_components([{
            "hostname": "Keiths-MacBook-Pro",
            "_report": {
                "findings": [],
                "inventory_findings": [{
                    "check_id": "AI-TOOL-003",
                    "status": "PASS",
                    "title": "OpenAI CLI detected",
                    "details": "openai pip package installed. Credential files have correct permissions.",
                    "evidence": [],
                }],
            },
        }])

        self.assertIn("openai cli / sdk", components["tools"])

    def test_aibom_reads_legacy_results_shape(self):
        components = _extract_components([{
            "hostname": "legacy-host",
            "_report": {"results": [{
                "check_id": "AI-TOOL-006",
                "status": "WARN",
                "title": "Cursor IDE detected",
                "details": "Cursor IDE is installed.",
                "evidence": [],
            }]},
        }])

        self.assertIn("cursor ide", components["tools"])


if __name__ == "__main__":
    unittest.main()
