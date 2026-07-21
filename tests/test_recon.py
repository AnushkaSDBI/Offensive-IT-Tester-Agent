"""
Tests for offensive_it_tester.core.recon: the live HTML/URL-parameter crawler.

Uses a fake requests.Session (no live network) so these tests are fast, deterministic,
and run in CI without needing a real target. The sandbox/target_app.py app is what a
human runs for the actual live-crawl demo; these tests verify the parsing logic.
"""
from offensive_it_tester.core.recon import _guess_vulns, _sanitize, crawl_surfaces


class FakeResponse:
    def __init__(self, text):
        self.text = text


class FakeSession:
    """Serves canned HTML for a couple of fake pages, no network access."""

    PAGES = {
        "http://fake.local/": """
            <html><body>
              <a href="/login">Login</a>
              <a href="/search?q=test">Search</a>
            </body></html>
        """,
        "http://fake.local/login": """
            <html><body>
              <form method="POST" action="/login">
                <input type="text" name="username">
                <input type="password" name="password">
                <input type="submit" value="Go">
              </form>
            </body></html>
        """,
        "http://fake.local/search": """
            <html><body>
              <form method="GET" action="/search">
                <input type="text" name="query">
              </form>
            </body></html>
        """,
    }

    def get(self, url, timeout=None):
        # strip query string for lookup, matching how the crawler queues clean URLs
        base = url.split("?")[0]
        return FakeResponse(self.PAGES.get(base, "<html></html>"))


# ---------------------------------------------------------------- helpers
def test_guess_vulns_matches_field_name():
    assert "SQLi" in _guess_vulns("username", "/login")
    assert "XSS" in _guess_vulns("comment", "/profile")
    assert "CmdInj" in _guess_vulns("host", "/ping")


def test_guess_vulns_matches_path_heuristic():
    assert "SQLi" in _guess_vulns("unrelated_field", "/login")


def test_guess_vulns_defaults_when_no_match():
    result = _guess_vulns("totally_unknown_xyz", "/nowhere")
    assert "XSS" in result and "SQLi" in result


def test_sanitize_strips_control_characters():
    assert _sanitize("hello\x00world\x1f") == "helloworld"


def test_sanitize_truncates_long_input():
    long_text = "A" * 500
    assert len(_sanitize(long_text)) == 200


# ---------------------------------------------------------------- crawl_surfaces
def test_crawl_discovers_login_form_fields():
    surfaces = crawl_surfaces("http://fake.local/", session=FakeSession(), max_pages=10)
    login_surfaces = [s for s in surfaces if s["path"] == "/login"]
    field_names = {s["parameter"] for s in login_surfaces}
    assert "username" in field_names
    assert "password" in field_names


def test_crawl_discovers_search_form_field():
    surfaces = crawl_surfaces("http://fake.local/", session=FakeSession(), max_pages=10)
    search_surfaces = [s for s in surfaces if s["path"] == "/search"]
    assert any(s["parameter"] == "query" for s in search_surfaces)


def test_crawl_assigns_expected_vulns_to_login_fields():
    surfaces = crawl_surfaces("http://fake.local/", session=FakeSession(), max_pages=10)
    username_surface = next(s for s in surfaces if s["path"] == "/login" and s["parameter"] == "username")
    assert "SQLi" in username_surface["expected_vulns"]


def test_crawl_deduplicates_surfaces():
    surfaces = crawl_surfaces("http://fake.local/", session=FakeSession(), max_pages=10)
    keys = [(s["path"], s["method"], s["parameter"]) for s in surfaces]
    assert len(keys) == len(set(keys))


def test_crawl_respects_max_pages():
    surfaces = crawl_surfaces("http://fake.local/", session=FakeSession(), max_pages=1)
    # with max_pages=1, only the index page is visited, so no form fields from
    # /login or /search should be discovered
    assert not any(s["path"] == "/login" for s in surfaces)


def test_crawl_marks_form_source():
    surfaces = crawl_surfaces("http://fake.local/", session=FakeSession(), max_pages=10)
    form_surfaces = [s for s in surfaces if s["source"] == "form"]
    assert len(form_surfaces) > 0
