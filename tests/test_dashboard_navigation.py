"""Regression test: refreshing the dashboard must keep the user on the
current page (URL-hash restore). Incident: a hardcoded restore whitelist
omitted endpoint-ai / network-assets / protected-cloud-assets, so
refreshing those pages bounced the user back to home."""

import re

import server


def _fleet_html(role: str = 'admin') -> str:
    return server._build_fleet_html([], current_user_role=role)


class TestRefreshRestoresPage:
    def test_hash_restore_matches_dom_not_whitelist(self):
        html = _fleet_html()
        assert "getElementById('page-' + hash)" in html
        # no hardcoded page whitelist deciding restoration (it silently
        # bounces unlisted pages to home whenever a new page is added)
        assert 'const valid' not in html

    def test_every_nav_target_has_a_restorable_page(self):
        html = _fleet_html()
        nav_targets = set(re.findall(r"navTo\('([a-z-]+)'\)", html))
        page_ids = set(re.findall(r'<div class="page[^"]*" id="page-([a-z-]+)"', html))
        missing = nav_targets - page_ids
        assert not missing, f'nav targets without a page div: {missing}'
        # every sidebar destination exists, therefore restores on refresh
        assert nav_targets <= page_ids

    def test_known_omitted_pages_are_navigable(self):
        # the three pages the old whitelist dropped
        html = _fleet_html()
        for page in ('endpoint-ai', 'network-assets', 'protected-cloud-assets'):
            assert f'id="page-{page}"' in html
            assert f"navTo('{page}')" in html

    def test_no_nav_to_nonexistent_scan_page(self):
        # runLiveScan previously called navTo('scan') — a page that does not
        # exist — dumping users on a blank view after starting a scan
        html = _fleet_html()
        assert "navTo('scan')" not in html
