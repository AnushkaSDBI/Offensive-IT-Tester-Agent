"""
The agent as a LangGraph state machine.

This is the executable form of the architecture diagram in the project documentation:
recon -> plan -> governance -> execute -> detect -> (loop or report). Two hard gates
(`check_scope`, called in `governance_node`) are deterministic and independent of the
planner -- no plan the LLM proposes can bypass them.
"""
from typing import Dict, List, Optional, Set, TypedDict

from langgraph.graph import END, StateGraph

from offensive_it_tester.agent.enforcer import verify_plan, sanitize_target_response
from offensive_it_tester.agent.planners import LLMPlanner
from offensive_it_tester.agent.session import get_session
from offensive_it_tester.agent.tools import (
    check_scope, detect_vulnerability, enumerate_surfaces, fire_payload, log_audit,
)


class AgentState(TypedDict):
    host: str
    port: int
    surfaces: List[dict]
    surface_idx: int                    # which surface plan_node will try next
    tried_idx: Dict[int, Set[int]]       # surface index -> corpus indices already tried there
    budget_remaining: int
    plan: Optional[dict]
    gov_allowed: bool
    response: dict
    results: List[dict]


def make_recon_node(ssvc_policy=None):
    """Recon node factory. If an SSVCPolicy is given, discovered surfaces are
    ranked by mission-impact priority before planning ever sees them, so
    high-value assets (e.g. /login) are tested before low-value ones, instead
    of plain discovery-order round-robin."""

    def recon_node(state: AgentState) -> AgentState:
        surfaces = enumerate_surfaces.invoke({})
        if ssvc_policy is not None:
            surfaces = ssvc_policy.rank_surfaces(surfaces)
        state["surfaces"] = surfaces
        state["surface_idx"] = 0
        log_audit.invoke({"action": "recon", "details": {
            "surfaces_found": len(surfaces),
            "ssvc_ranked": ssvc_policy is not None,
        }, "result": "OK"})
        return state

    return recon_node


def recon_node(state: AgentState) -> AgentState:
    """Backward-compatible default (no SSVC ranking)."""
    return make_recon_node(None)(state)


def make_plan_node(planner: LLMPlanner):
    """Round-robin across surfaces: each call advances to the NEXT surface, so a
    limited budget is spread across attack classes and injection points instead of
    exhausting one surface's payload list before ever trying another."""

    def plan_node(state: AgentState) -> AgentState:
        session = get_session()
        n = len(state["surfaces"])
        checked = 0
        while checked < n:
            idx = state["surface_idx"]
            surface = state["surfaces"][idx]
            tried_here = state["tried_idx"].setdefault(idx, set())
            plan = planner.plan(surface, session.corpus, tried_here)
            state["surface_idx"] = (idx + 1) % n
            if plan is not None:
                state["plan"] = {**plan, "surface": surface, "surface_key": idx}
                log_audit.invoke({
                    "action": "plan",
                    "details": {"attack_class": plan["attack_class"], "planner": planner.name,
                                "rationale": plan["rationale"]},
                    "result": "PLANNED",
                })
                return state
            checked += 1
        state["plan"] = None
        return state

    return plan_node


def governance_node(state: AgentState) -> AgentState:
    p, surface = state["plan"], state["plan"]["surface"]
    # Deterministic enforcer: hardcoded Python checks BEFORE the scope gate.
    # This cannot be prompt-injected because it is not an LLM judgment.
    enforcer_ok, enforcer_reason = verify_plan(state["plan"])
    if not enforcer_ok:
        state["gov_allowed"] = False
        log_audit.invoke({
            "action": "enforcer_block",
            "details": {"surface": surface["path"], "attack_class": p["attack_class"]},
            "result": enforcer_reason,
        })
        state["results"].append({
            "surface": surface["path"], "attack_class": p["attack_class"],
            "status": "BLOCKED", "reason": enforcer_reason,
        })
        state["tried_idx"][p["surface_key"]].add(p["corpus_index"])
        state["budget_remaining"] -= 1
        return state
    result = check_scope.invoke({
        "host": state["host"], "port": state["port"],
        "method": surface["method"], "payload": p["payload"],
    })
    state["gov_allowed"] = result["allowed"]
    log_audit.invoke({
        "action": "scope_check",
        "details": {"surface": surface["path"], "attack_class": p["attack_class"]},
        "result": result["reason"],
    })
    if not result["allowed"]:
        state["results"].append({
            "surface": surface["path"], "attack_class": p["attack_class"],
            "status": "BLOCKED", "reason": result["reason"],
        })
        state["tried_idx"][p["surface_key"]].add(p["corpus_index"])
        state["budget_remaining"] -= 1
    return state


def execute_node(state: AgentState) -> AgentState:
    p, surface = state["plan"], state["plan"]["surface"]
    resp = fire_payload.invoke({
        "path": surface["path"], "method": surface["method"], "parameter": surface["parameter"],
        "payload": p["payload"], "attack_class": p["attack_class"],
    })
    # Context isolation: sanitize the target's response before it enters agent state
    resp["body"] = sanitize_target_response(resp["body"])
    state["response"] = resp
    log_audit.invoke({
        "action": "request_sent",
        "details": {"path": surface["path"], "attack_class": p["attack_class"]},
        "result": f"status={resp['status_code']}",
    })
    return state


def detect_node(state: AgentState) -> AgentState:
    p, surface, resp = state["plan"], state["plan"]["surface"], state["response"]
    det = detect_vulnerability.invoke({
        "attack_class": p["attack_class"], "payload": p["payload"],
        "response_body": resp["body"], "response_code": resp["status_code"],
        "response_time": resp["response_time"],
    })
    log_audit.invoke({
        "action": "detection",
        "details": {"attack_class": p["attack_class"], "confidence": det["confidence"]},
        "result": "VULNERABLE" if det["vulnerable"] else "not vulnerable",
    })
    state["results"].append({
        "surface": surface["path"], "attack_class": p["attack_class"], "status": "TESTED",
        "vulnerable": det["vulnerable"], "confidence": det["confidence"], "rationale": p["rationale"],
    })
    state["tried_idx"][p["surface_key"]].add(p["corpus_index"])
    state["budget_remaining"] -= 1
    # SEPARATION OF POWERS: strip the raw response body from state before it
    # loops back to plan_node. The planner only ever sees structured metadata
    # (class, vulnerable, confidence), never raw HTML/text from the target.
    # This prevents a malicious target from injecting instructions into the
    # planner's next decision via a poisoned response body.
    state["response"] = {"status_code": resp["status_code"],
                         "response_time": resp["response_time"],
                         "body": "[REDACTED: raw body stripped before planner loop]"}
    return state


def report_node(state: AgentState) -> AgentState:
    return state


def _route_after_plan(state):
    return "governance" if state["plan"] else "report"


def _route_after_gov(state):
    return "execute" if state["gov_allowed"] else "plan"


def _route_after_detect(state):
    return "report" if state["budget_remaining"] <= 0 else "plan"


def build_graph(planner: LLMPlanner, ssvc_policy=None):
    """Compile the state machine with the given planner. Everything else -- the
    gates, the tools, the routing -- is identical regardless of which planner is used.

    ssvc_policy: optional SSVCPolicy (see ssvc_policy.py). If given, recon ranks
    discovered surfaces by mission-impact priority instead of discovery order.
    """
    graph = StateGraph(AgentState)
    plan_node = make_plan_node(planner)
    recon = make_recon_node(ssvc_policy)
    for name, fn in [
        ("recon", recon), ("plan", plan_node), ("governance", governance_node),
        ("execute", execute_node), ("detect", detect_node), ("report", report_node),
    ]:
        graph.add_node(name, fn)

    graph.set_entry_point("recon")
    graph.add_edge("recon", "plan")
    graph.add_conditional_edges("plan", _route_after_plan, {"governance": "governance", "report": "report"})
    graph.add_conditional_edges("governance", _route_after_gov, {"execute": "execute", "plan": "plan"})
    graph.add_edge("execute", "detect")
    graph.add_conditional_edges("detect", _route_after_detect, {"plan": "plan", "report": "report"})
    graph.add_edge("report", END)

    return graph.compile()
