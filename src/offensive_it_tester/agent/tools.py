"""
Agent tools: typed, named, documented functions the LangGraph agent (and, if enabled,
an LLM) calls. Each wraps `offensive_it_tester.core` logic; none reimplement security
logic here. This is the same tool-calling pattern used throughout the notebook's
Section 5C, extracted into an importable module.
"""
import html
import urllib.parse

from langchain_core.tools import tool

from offensive_it_tester.agent.session import get_session


@tool
def normalize_input(text: str) -> str:
    """Decode URL-encoding and HTML entities and lowercase the text, so an obfuscated
    payload cannot evade downstream pattern checks."""
    return html.unescape(urllib.parse.unquote(str(text))).lower()


@tool
def enumerate_surfaces() -> list:
    """Return every testable (path, method, parameter) surface on the authorized
    target, with the vulnerability classes expected at each surface."""
    return get_session().target.enumerate_surfaces()


@tool
def check_scope(host: str, port: int, method: str, payload: str) -> dict:
    """Mandatory gate. Returns {'allowed': bool, 'reason': str}. Checks host, port,
    method, time window, destructive-content, and rate limit in one call. Must be
    called, and must return allowed=True, before fire_payload is ever called."""
    session = get_session()
    allowed, reason = session.gate.check(host, port, method, payload)
    return {"allowed": allowed, "reason": reason}


@tool
def fire_payload(path: str, method: str, parameter: str, payload: str, attack_class: str) -> dict:
    """Send one payload to one parameter on the authorized target and capture the
    response. Only call after check_scope has returned allowed=True."""
    session = get_session()
    session.gate.record_request()
    return session.target.send_request(path, method, parameter, payload, attack_class=attack_class)


@tool
def detect_vulnerability(
    attack_class: str, payload: str, response_body: str, response_code: int, response_time: float
) -> dict:
    """Run the non-destructive, class-specific detector on a captured response and
    return a dict including at least {'vulnerable': bool, 'confidence': str}."""
    session = get_session()
    detector = session.detectors.get(attack_class)
    if not detector:
        return {"vulnerable": False, "confidence": "none", "evidence": []}
    return detector.check(payload, response_body, response_code, response_time)


@tool
def log_audit(action: str, details: dict, result: str) -> str:
    """Append one immutable entry to the audit log. Called after every gate decision,
    every fired payload, and every detection result. Returns the entry id."""
    session = get_session()
    entry = session.audit.log(action, details, result)
    return entry["entry_id"]


TOOLS = [normalize_input, enumerate_surfaces, check_scope, fire_payload, detect_vulnerability, log_audit]
