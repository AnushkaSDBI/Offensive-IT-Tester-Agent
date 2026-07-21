"""
Unit tests for offensive_it_tester.core: scope gate properties, detector correctness,
and the regression tests for the two bugs the original weakness suite found and fixed
(SSRF over-breadth, CmdInj bare-substring false positives -- see docs/ for the full
found-then-fixed story).

Run with:
    pytest --cov=offensive_it_tester.core --cov-report=term-missing
"""
from datetime import datetime, timedelta

from offensive_it_tester.core import (
    AuditLog, MockTarget, ScopeDefinition, ScopeGate, build_detectors, default_scope,
)


def make_gate(**overrides):
    defaults = dict(authorized_hosts={"127.0.0.1"}, authorized_ports={80}, max_requests_per_minute=100)
    defaults.update(overrides)
    return ScopeGate(ScopeDefinition(**defaults))


# ---------------------------------------------------------------- scope gate
def test_allows_valid_request():
    assert make_gate().check("127.0.0.1", 80, "GET", "' OR 1=1--")[0]


def test_blocks_unauthorized_host():
    assert not make_gate().check("evil.com", 80, "GET", "x")[0]


def test_blocks_unauthorized_port():
    assert not make_gate().check("127.0.0.1", 3306, "GET", "x")[0]


def test_blocks_disallowed_method():
    assert not make_gate().check("127.0.0.1", 80, "DELETE", "x")[0]


def test_blocks_destructive_payload():
    assert not make_gate().check("127.0.0.1", 80, "GET", "'; DROP TABLE users--")[0]


def test_blocks_outside_time_window():
    scope = ScopeDefinition(
        authorized_hosts={"127.0.0.1"}, authorized_ports={80},
        test_window_start=datetime.now() - timedelta(hours=3),
        test_window_end=datetime.now() - timedelta(hours=1),
    )
    assert not ScopeGate(scope).check("127.0.0.1", 80, "GET", "x")[0]


def test_enforces_rate_limit():
    gate = make_gate(max_requests_per_minute=2)
    for _ in range(2):
        gate.record_request()
    assert not gate.check("127.0.0.1", 80, "GET", "x")[0]


# ---------------------------------------------------------------- detectors: true positives
def test_sqli_detects_error_string():
    assert build_detectors()["SQLi"].check("'", "You have an error in your SQL syntax", 500, 0.1)["vulnerable"]


def test_sqli_detects_timing():
    assert build_detectors()["SQLi"].check("' or sleep(6)--", "ok", 200, 6.0)["vulnerable"]


def test_xss_detects_reflection():
    payload = "<script>alert(1)</script>"
    assert build_detectors()["XSS"].check(payload, f"result: {payload}", 200, 0.1)["vulnerable"]


def test_csrf_detects_accepted_without_token():
    assert build_detectors()["CSRF"].check("x", "Transfer successful", 200, 0.1)["vulnerable"]


def test_ssrf_detects_metadata_signature():
    assert build_detectors()["SSRF"].check("x", "instance-id: i-0abc", 200, 0.1)["vulnerable"]


def test_ssrf_detects_private_ip():
    assert build_detectors()["SSRF"].check("x", "connected to 169.254.169.254", 200, 0.1)["vulnerable"]


def test_cmdinj_detects_canary():
    assert build_detectors()["CmdInj"].check("x", "out: pentest_canary_12345", 200, 0.1)["vulnerable"]


def test_cmdinj_detects_structured_output():
    assert build_detectors()["CmdInj"].check("; id", "uid=33(www-data) gid=33", 200, 0.1)["vulnerable"]


# ---------------------------------------------------------------- detectors: regression (found-then-fixed)
def test_sqli_clears_benign_response():
    assert not build_detectors()["SQLi"].check("hi", "Welcome", 200, 0.1)["vulnerable"]


def test_ssrf_ignores_bare_localhost_mention():
    """Regression test for the SSRF over-breadth bug: a response that merely
    mentions 'localhost'/'internal' in ordinary prose must not be flagged."""
    body = "runs on localhost in dev; internal team only"
    assert not build_detectors()["SSRF"].check("x", body, 200, 0.1)["vulnerable"]


def test_cmdinj_ignores_bare_uid_substring():
    """Regression test for the CmdInj false-positive bug: bare text containing
    'uid=' or '/bin/' must not be flagged without a structured command-output shape."""
    body = "the uid= parameter and /bin/ folder are documented below"
    assert not build_detectors()["CmdInj"].check("x", body, 200, 0.1)["vulnerable"]


def test_csrf_clears_when_token_required():
    assert not build_detectors()["CSRF"].check("x", "csrf token required", 403, 0.1)["vulnerable"]


# ---------------------------------------------------------------- audit log
def test_audit_log_is_append_only_and_ordered():
    log = AuditLog("scope-123")
    log.log("scope_check", {"host": "127.0.0.1"}, "ALLOWED")
    log.log("detection", {"class": "SQLi"}, "VULNERABLE")
    assert len(log.entries) == 2
    assert log.entries[0]["action"] == "scope_check"
    assert "Entries: 2" in log.summary()


def test_audit_log_empty_summary():
    assert AuditLog("scope-empty").summary() == "No entries."


# ---------------------------------------------------------------- mock target
def test_mock_target_enumerates_all_surfaces():
    surfaces = MockTarget().enumerate_surfaces()
    assert len(surfaces) > 0
    assert all({"path", "method", "parameter", "expected_vulns"} <= set(s) for s in surfaces)


def test_mock_target_simulates_sqli_error():
    resp = MockTarget().send_request("/login", "POST", "username", "' OR 1=1--", attack_class="SQLi")
    assert resp["status_code"] == 500
    assert "syntax" in resp["body"].lower()


def test_mock_target_simulates_xss_reflection():
    resp = MockTarget().send_request("/search", "GET", "query", "<script>alert(1)</script>", attack_class="XSS")
    assert "<script>alert(1)</script>" in resp["body"]


def test_mock_target_simulates_cmdinj_output():
    resp = MockTarget().send_request("/ping", "POST", "host", "; id", attack_class="CmdInj")
    assert "uid=33" in resp["body"]


def test_mock_target_simulates_ssrf_internal_response():
    resp = MockTarget().send_request("/fetch", "GET", "url", "http://127.0.0.1/", attack_class="SSRF")
    assert "internal service data" in resp["body"]


def test_mock_target_simulates_csrf_accepted():
    resp = MockTarget().send_request("/transfer", "POST", "amount", "100", attack_class="CSRF")
    assert resp["status_code"] == 200
    assert "successful" in resp["body"].lower()


def test_mock_target_default_response_for_unrecognized_path():
    resp = MockTarget().send_request("/unknown", "GET", "q", "harmless", attack_class="XSS")
    assert resp["status_code"] == 200


def test_mock_target_rag_poisoned_response():
    resp = MockTarget().send_request("/api/knowledge", "GET", "query", "inject poison test",
                                      attack_class="RAGPoisoning")
    assert "ignore previous instructions" in resp["body"]


def test_mock_target_rag_clean_response():
    resp = MockTarget().send_request("/api/knowledge", "GET", "query", "normal search",
                                      attack_class="RAGPoisoning")
    assert "ignore previous instructions" not in resp["body"]


def test_mock_target_mcp_poisoned_response():
    resp = MockTarget().send_request("/api/mcp/tools", "GET", "discover", "poison probe",
                                      attack_class="MCPToolPoisoning")
    assert "evil.example" in resp["body"]


def test_mock_target_mcp_clean_response():
    resp = MockTarget().send_request("/api/mcp/tools", "GET", "discover", "normal probe",
                                      attack_class="MCPToolPoisoning")
    assert "evil.example" not in resp["body"]


# ---------------------------------------------------------------- default_scope
def test_default_scope_matches_documented_lab_targets():
    scope = default_scope()
    assert scope.authorized_hosts == {"127.0.0.1", "localhost", "dvwa.local"}
    assert scope.authorized_ports == {80, 8080, 5001}
    assert scope.max_requests_per_minute == 30


# ---------------------------------------------------------------- hash-chained audit log
def test_audit_chain_is_valid_after_normal_use():
    log = AuditLog("scope-chain-test")
    log.log("scope_check", {"host": "127.0.0.1"}, "ALLOWED")
    log.log("request_sent", {"path": "/login"}, "status=500")
    log.log("detection", {"class": "SQLi"}, "VULNERABLE")
    valid, findings = log.verify()
    assert valid, f"chain should be intact: {findings}"
    assert len(log.entries) == 3


def test_audit_chain_detects_tampering():
    log = AuditLog("scope-tamper-test")
    log.log("scope_check", {"host": "127.0.0.1"}, "ALLOWED")
    log.log("detection", {"class": "SQLi"}, "VULNERABLE")
    # tamper: modify a record after it was logged
    log.entries[0]["result"] = "BLOCKED"  # was "ALLOWED"
    valid, findings = log.verify()
    assert not valid, "chain should detect the tamper"
    assert any("tampered" in f for f in findings)


def test_audit_chain_detects_deletion():
    log = AuditLog("scope-delete-test")
    log.log("a", {}, "1")
    log.log("b", {}, "2")
    log.log("c", {}, "3")
    # delete the middle entry
    del log.entries[1]
    valid, findings = log.verify()
    assert not valid, "chain should detect the missing entry"


def test_audit_summary_shows_integrity():
    log = AuditLog("scope-summary-test")
    log.log("x", {}, "ok")
    summary = log.summary()
    assert "INTACT" in summary
