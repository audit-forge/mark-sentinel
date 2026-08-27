"""N/A short-circuit tests for non-AI systems in deploy/supply/gov checks."""
from connectors.config_connector import ScanContext
from checks.deploy import check_deploy_004
from checks.supply_chain import check_supply_003, check_supply_005
from checks.governance import check_gov_005
from checks import NA, PASS, FAIL, WARN


def make_ctx(files: dict) -> ScanContext:
    ctx = ScanContext(target_dir="/fake/target")
    ctx.files = files
    # Mirror the derived fields that config_connector populates from the walk.
    ctx.docker_compose_raw = ""
    ctx.requirements_txt = ""
    ctx.inventory_files = []
    for path, content in files.items():
        if path.endswith(("docker-compose.yml", "docker-compose.yaml")):
            ctx.docker_compose_raw = content
        if path.endswith("requirements.txt"):
            ctx.requirements_txt = content
        if "inventory" in path.lower() or "aibom" in path.lower():
            ctx.inventory_files.append(path)
    return ctx


def test_deploy_004_na_when_no_ai():
    ctx = make_ctx({"docker-compose.yml": "services:\n  web:\n    image: nginx"})
    res = check_deploy_004(ctx)
    assert res.status == NA
    assert "No AI/LLM endpoint detected" in res.details


def test_supply_003_na_when_no_ai():
    ctx = make_ctx({"README.md": "# plain app"})
    res = check_supply_003(ctx)
    assert res.status == NA
    assert "No AI/LLM usage detected" in res.details


def test_supply_005_na_when_no_ai():
    ctx = make_ctx({"docker-compose.yml": "services:\n  web:\n    image: nginx"})
    res = check_supply_005(ctx)
    assert res.status == NA
    assert "No AI/LLM usage detected" in res.details


def test_gov_005_na_when_no_ai():
    ctx = make_ctx({"compliance/ai_asset_inventory.md": "# AI Inventory\n\nNo systems yet."})
    res = check_gov_005(ctx)
    assert res.status == NA
    assert "No AI/LLM systems detected" in res.details


def test_deploy_004_evaluates_when_ai_present():
    """With AI signals and exposed ports, check runs its normal logic (FAIL because no auth)."""
    ctx = make_ctx({
        "ai_config.json": '{"ai_inference_enabled": true}',
        "docker-compose.yml": "services:\n  api:\n    image: app:1.0\n    ports:\n      - 8080:8080",
    })
    res = check_deploy_004(ctx)
    assert res.status == FAIL


def test_supply_003_evaluates_when_ai_present():
    ctx = make_ctx({
        "requirements.txt": "openai==1.68.2\nflask==2.3.0\n",
    })
    res = check_supply_003(ctx)
    assert res.status == PASS


def test_supply_005_evaluates_when_ai_present():
    ctx = make_ctx({
        "config.json": '{"model": "gpt-4o-2024-08-06"}',
    })
    res = check_supply_005(ctx)
    assert res.status == PASS


def test_gov_005_evaluates_when_ai_present():
    # Include enough inventory quality indicators to PASS.
    ctx = make_ctx({
        "ai_config.json": '{"ai_inference_enabled": true}',
        "compliance/ai_asset_inventory.md": (
            "# AI Inventory\n\n"
            "| System | Provider | Model | Data Processed | Owner | Last Reviewed |\n"
            "|--------|----------|-------|----------------|-------|---------------|\n"
            "| Chat | OpenAI | gpt-4o | customer prompts | owner@example.com | 2026-08-27 |\n"
        ),
    })
    res = check_gov_005(ctx)
    assert res.status == PASS
