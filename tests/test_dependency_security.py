"""Keep audited dependency floors and Starlette's template API compatible."""

import ast
from pathlib import Path

import pytest
from packaging.requirements import Requirement
from packaging.version import Version


REPO = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("package,minimum", [
    ("fastapi", "0.162.0"),
    ("starlette", "1.10.0"),
    ("PyJWT", "2.15.1"),
    ("python-multipart", "0.0.32"),
    ("requests", "2.34.2"),
])
def test_admin_security_dependencies_are_pinned_above_audited_floor(package, minimum):
    requirements = [
        Requirement(line) for line in (REPO / "admin/requirements.txt").read_text().splitlines()
        if line.strip() and not line.startswith("#")
    ]
    requirement = next(item for item in requirements if item.name.lower() == package.lower())
    pins = list(requirement.specifier)
    assert len(pins) == 1 and pins[0].operator == "=="
    assert Version(pins[0].version) >= Version(minimum)


def test_all_admin_template_calls_use_request_name_context_signature():
    tree = ast.parse((REPO / "admin/app.py").read_text())
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Attribute) and node.func.attr == "TemplateResponse"]
    assert calls
    for call in calls:
        assert not call.args, f"Legacy positional template call at line {call.lineno}"
        keywords = {item.arg: item.value for item in call.keywords}
        assert {"request", "name", "context"} <= keywords.keys()
        assert isinstance(keywords["request"], ast.Name)
        assert keywords["request"].id == "request"
