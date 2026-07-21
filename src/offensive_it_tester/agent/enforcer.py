"""
Deterministic enforcer: hardcoded Python verification hooks that intercept every
planner output BEFORE it reaches the tools.

Aegissec-inspired principle: never rely solely on the LLM following its system prompt.
The planner proposes, this module disposes. Every proposed action is checked against
the same ScopeGate rules, plus additional content-safety checks (prompt injection
signatures, PII patterns, out-of-corpus payloads) that the scope gate doesn't cover.

If any check fails, the action is blocked and logged, the planner never learns why
(to avoid teaching it to evade the enforcer).
"""
import re
from typing import Optional

from offensive_it_tester.agent.session import get_session


# Patterns that suggest the target page is trying to inject instructions into the agent
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(previous|above|all)\s+(instructions|rules)", re.I),
    re.compile(r"you\s+are\s+now\s+a", re.I),
    re.compile(r"system\s*:\s*", re.I),
    re.compile(r"<\|im_start\|>", re.I),
    re.compile(r"\[INST\]", re.I),
    re.compile(r"do\s+not\s+follow\s+(the\s+)?scope", re.I),
]

# PII patterns that should never appear in a payload the planner constructs
PII_PATTERNS = [
    re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),           # SSN
    re.compile(r"\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b"),  # IBAN
    re.compile(r"\b\d{16}\b"),                        # credit card (rough)
]


def verify_plan(plan: Optional[dict]) -> tuple:
    """Check a planner's proposed action. Returns (allowed: bool, reason: str).

    This runs AFTER the planner returns and BEFORE any tool is called. It is
    deterministic Python, not an LLM judgment, so it cannot be prompt-injected.
    """
    if plan is None:
        return True, "no plan (exhausted)"

    session = get_session()
    payload = str(plan.get("payload", ""))
    attack_class = str(plan.get("attack_class", ""))
    corpus_index = plan.get("corpus_index")

    # 1. The payload must come from the reviewed corpus, not free-generated
    if corpus_index is not None:
        if corpus_index not in session.corpus.index:
            return False, "enforcer: corpus_index not in reviewed corpus"
        corpus_payload = str(session.corpus.loc[corpus_index, "payload"])
        if payload != corpus_payload:
            return False, "enforcer: payload text does not match corpus entry"

    # 2. The attack class must be one of the five known classes
    if attack_class not in {"SQLi", "XSS", "CSRF", "SSRF", "CmdInj"}:
        return False, f"enforcer: unknown attack_class '{attack_class}'"

    # 3. Check for prompt-injection signatures in the payload
    for pattern in PROMPT_INJECTION_PATTERNS:
        if pattern.search(payload):
            return False, "enforcer: prompt-injection signature detected in payload"

    # 4. Check for PII that should never be in a test payload
    for pattern in PII_PATTERNS:
        if pattern.search(payload):
            return False, "enforcer: PII pattern detected in payload"

    # 5. Run the scope gate's destructive-content check
    if session.gate.scope.contains_blocked_content(payload):
        return False, "enforcer: destructive content"

    return True, "enforcer: APPROVED"


def sanitize_target_response(response_body: str, max_len: int = 10000) -> str:
    """Context isolation: sanitize any text retrieved from the target before it
    enters agent state or is shown to the planner.

    Strips prompt-injection attempts and truncates to prevent context-window
    flooding. The raw response is still available in the audit log for forensics.
    """
    clean = response_body[:max_len]
    for pattern in PROMPT_INJECTION_PATTERNS:
        clean = pattern.sub("[BLOCKED_INJECTION_ATTEMPT]", clean)
    return clean
