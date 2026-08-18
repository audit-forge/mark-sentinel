from pathlib import Path


REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / "admin" / "app.py").read_text()


def test_customer_ids_are_limited_to_safe_container_and_path_components():
    assert '_CUSTOMER_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")' in SOURCE
    assert SOURCE.count("if not _is_valid_customer_id(customer_id):") == 2
    assert "if not _is_valid_customer_id(cid):" in SOURCE


def test_shadow_ai_query_passes_customer_id_as_an_argument():
    assert "customer_id = sys.argv[1]" in SOURCE
    assert '""", customer_id,' in SOURCE
    assert "f\"\"\"\nimport sqlite3" not in SOURCE


def test_auth_cookie_can_cover_the_canonical_dashboard_subdomain():
    assert "AUTH_COOKIE_DOMAIN" in SOURCE
    assert "secure=bool(AUTH_COOKIE_DOMAIN)" in SOURCE
