"""Unit tests for agent_core. Encodes security properties + the fixed-bug regressions."""
from datetime import datetime, timedelta
from agent_core import ScopeDefinition, ScopeGate, build_detectors, MockTarget, default_scope

def make_gate():
    return ScopeGate(ScopeDefinition(authorized_hosts={'127.0.0.1'}, authorized_ports={80}, max_requests_per_minute=100))

# ---- scope gate ----
def test_allows_valid():
    assert make_gate().check('127.0.0.1', 80, 'GET', "' OR 1=1--")[0]
def test_blocks_host():
    assert not make_gate().check('evil.com', 80, 'GET', 'x')[0]
def test_blocks_port():
    assert not make_gate().check('127.0.0.1', 3306, 'GET', 'x')[0]
def test_blocks_method():
    assert not make_gate().check('127.0.0.1', 80, 'DELETE', 'x')[0]
def test_blocks_destructive():
    assert not make_gate().check('127.0.0.1', 80, 'GET', "'; DROP TABLE users--")[0]
def test_blocks_out_of_window():
    s = ScopeDefinition(authorized_hosts={'127.0.0.1'}, authorized_ports={80},
                        test_window_start=datetime.now() - timedelta(hours=3),
                        test_window_end=datetime.now() - timedelta(hours=1))
    assert not ScopeGate(s).check('127.0.0.1', 80, 'GET', 'x')[0]
def test_rate_limit():
    g = ScopeGate(ScopeDefinition(authorized_hosts={'127.0.0.1'}, authorized_ports={80}, max_requests_per_minute=2))
    for _ in range(2): g.record_request()
    assert not g.check('127.0.0.1', 80, 'GET', 'x')[0]

# ---- detectors: true positives ----
def test_sqli_error():
    assert build_detectors()['SQLi'].check("'", "You have an error in your SQL syntax", 500, 0.1)['vulnerable']
def test_sqli_timing():
    assert build_detectors()['SQLi'].check("' or sleep(6)--", "ok", 200, 6.0)['vulnerable']
def test_xss_reflected():
    p = "<script>alert(1)</script>"
    assert build_detectors()['XSS'].check(p, f"result: {p}", 200, 0.1)['vulnerable']
def test_csrf_accepted():
    assert build_detectors()['CSRF'].check("x", "Transfer successful", 200, 0.1)['vulnerable']
def test_ssrf_metadata():
    assert build_detectors()['SSRF'].check("x", "instance-id: i-0abc", 200, 0.1)['vulnerable']
def test_ssrf_private_ip():
    assert build_detectors()['SSRF'].check("x", "connected to 169.254.169.254", 200, 0.1)['vulnerable']
def test_cmdinj_canary():
    assert build_detectors()['CmdInj'].check("x", "out: pentest_canary_12345", 200, 0.1)['vulnerable']
def test_cmdinj_structured():
    assert build_detectors()['CmdInj'].check("; id", "uid=33(www-data) gid=33", 200, 0.1)['vulnerable']

# ---- detectors: fixed false positives (regression tests) ----
def test_sqli_clears_benign():
    assert not build_detectors()['SQLi'].check("hi", "Welcome", 200, 0.1)['vulnerable']
def test_ssrf_ignores_bare_localhost():
    assert not build_detectors()['SSRF'].check("x", "runs on localhost in dev; internal team", 200, 0.1)['vulnerable']
def test_cmdinj_ignores_bare_uid_text():
    assert not build_detectors()['CmdInj'].check("x", "the uid= parameter and /bin/ folder", 200, 0.1)['vulnerable']
def test_csrf_clears_with_token():
    assert not build_detectors()['CSRF'].check("x", "csrf token required", 403, 0.1)['vulnerable']

# ---- MockTarget (added: these branches were untested, dragging coverage to 73%) ----
def test_mock_enumerate_surfaces():
    surfaces = MockTarget().enumerate_surfaces()
    assert len(surfaces) > 0
    assert all({'path', 'method', 'parameter', 'expected_vulns'} <= set(s) for s in surfaces)

def test_mock_sqli_error_response():
    r = MockTarget().send_request('/login', 'POST', 'username', "' OR 1=1--", attack_class='SQLi')
    assert r['status_code'] == 500 and 'syntax' in r['body'].lower()

def test_mock_xss_reflects_payload():
    r = MockTarget().send_request('/search', 'GET', 'query', '<script>alert(1)</script>', attack_class='XSS')
    assert '<script>alert(1)</script>' in r['body']

def test_mock_cmdinj_output():
    r = MockTarget().send_request('/ping', 'POST', 'host', '; id', attack_class='CmdInj')
    assert 'uid=33' in r['body']

def test_mock_ssrf_internal_response():
    r = MockTarget().send_request('/fetch', 'GET', 'url', 'http://127.0.0.1/', attack_class='SSRF')
    assert 'internal service data' in r['body']

def test_mock_csrf_accepted():
    r = MockTarget().send_request('/transfer', 'POST', 'amount', '100', attack_class='CSRF')
    assert r['status_code'] == 200 and 'successful' in r['body'].lower()

def test_mock_default_response_unrecognized_path():
    r = MockTarget().send_request('/unknown', 'GET', 'q', 'harmless', attack_class='XSS')
    assert r['status_code'] == 200

# ---- default_scope ----
def test_default_scope_matches_documented_lab():
    s = default_scope()
    assert s.authorized_hosts == {'127.0.0.1', 'localhost', 'dvwa.local'}
    assert s.authorized_ports == {80, 8080, 5001}
    assert s.max_requests_per_minute == 30
