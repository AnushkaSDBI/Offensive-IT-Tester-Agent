"""
Authorization scope gate.

This is the mandatory, deterministic control every outbound agent action must pass
through. It is intentionally independent of the LLM planner (see
`offensive_it_tester.agent.planners`) so that no planning error, prompt injection, or
model mistake can route an action outside the authorized test scope.

Covered at 100% by tests/test_agent_core.py.
"""
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Set


@dataclass
class ScopeDefinition:
    """The authorized test scope: which hosts, ports, methods, time window, and
    content patterns are permitted. Everything else is refused by ScopeGate."""

    authorized_hosts: Set[str] = field(default_factory=set)
    authorized_ports: Set[int] = field(default_factory=set)
    allowed_methods: Set[str] = field(default_factory=lambda: {"GET", "POST"})
    blocked_payloads: Set[str] = field(
        default_factory=lambda: {"DROP", "DELETE FROM", "rm -rf", "shutdown"}
    )
    max_requests_per_minute: int = 10
    test_window_start: datetime = field(default_factory=datetime.now)
    test_window_end: datetime = field(
        default_factory=lambda: datetime.now() + timedelta(hours=2)
    )

    def is_host_authorized(self, host: str) -> bool:
        return host in self.authorized_hosts

    def is_port_authorized(self, port: int) -> bool:
        return port in self.authorized_ports

    def is_within_window(self) -> bool:
        return self.test_window_start <= datetime.now() <= self.test_window_end

    def contains_blocked_content(self, payload: str) -> bool:
        upper = payload.upper()
        return any(b.upper() in upper for b in self.blocked_payloads)


class ScopeGate:
    """Five checks in one gate: host, port, method, time window, and destructive
    content, plus a sliding-window rate limit. Rejections carry a specific reason
    (`"host"`, `"port"`, `"method"`, `"window"`, `"destructive"`, `"rate"`) so callers
    and the audit log can distinguish why a request was refused."""

    def __init__(self, scope: ScopeDefinition):
        self.scope = scope
        self.request_timestamps: list[float] = []

    def check(self, host: str, port: int, method: str, payload: str):
        if not self.scope.is_host_authorized(host):
            return False, "host"
        if not self.scope.is_port_authorized(port):
            return False, "port"
        if method.upper() not in self.scope.allowed_methods:
            return False, "method"
        if not self.scope.is_within_window():
            return False, "window"
        if self.scope.contains_blocked_content(payload):
            return False, "destructive"

        now = time.time()
        self.request_timestamps = [t for t in self.request_timestamps if now - t < 60]
        if len(self.request_timestamps) >= self.scope.max_requests_per_minute:
            return False, "rate"

        return True, "ALLOWED"

    def record_request(self):
        self.request_timestamps.append(time.time())


def default_scope() -> ScopeDefinition:
    """The authorized lab scope used throughout the notebook and the demo agent."""
    return ScopeDefinition(
        authorized_hosts={"127.0.0.1", "localhost", "dvwa.local"},
        authorized_ports={80, 8080, 5001},
        max_requests_per_minute=30,
    )
