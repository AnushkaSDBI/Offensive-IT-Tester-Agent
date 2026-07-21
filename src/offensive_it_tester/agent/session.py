"""
Shared agent session state.

LangChain `@tool`-decorated functions are plain functions, not methods, so they need
a place to find the current scope gate, audit log, target, detectors, and payload
corpus. This module holds exactly that, set once via `init_session(...)` before the
graph runs. This mirrors the pattern used in the source notebook (module-level
instances), made explicit and configurable instead of hardcoded.
"""
from dataclasses import dataclass
from typing import Optional

import pandas as pd

from offensive_it_tester.core import AuditLog, MockTarget, ScopeDefinition, ScopeGate, build_detectors


@dataclass
class AgentSession:
    gate: ScopeGate
    audit: AuditLog
    target: MockTarget
    detectors: dict
    corpus: pd.DataFrame


_session: Optional[AgentSession] = None


def init_session(
    scope: ScopeDefinition,
    corpus: pd.DataFrame,
    target: Optional[MockTarget] = None,
) -> AgentSession:
    """Create and register the active agent session. Must be called before any tool
    in `offensive_it_tester.agent.tools` is invoked."""
    global _session
    _session = AgentSession(
        gate=ScopeGate(scope),
        audit=AuditLog(id(scope).__str__()[:8]),
        target=target or MockTarget(),
        detectors=build_detectors(),
        corpus=corpus,
    )
    return _session


def get_session() -> AgentSession:
    if _session is None:
        raise RuntimeError(
            "No active agent session. Call offensive_it_tester.agent.session.init_session(...) first."
        )
    return _session
