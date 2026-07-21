"""
Run the agent end to end against the mock target and print results.

This is the smallest possible reproduction of what the notebook's Section 5C.4 does,
as a plain script: build a session, compile the graph, invoke it, print what happened.

Usage:
    python run_agent.py --corpus data/processed/payloads_clean.csv --budget 30
"""
import argparse
import pprint

import pandas as pd

from offensive_it_tester.agent import build_graph, get_planner, init_session, default_policy
from offensive_it_tester.core import MockTarget, default_scope


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default="data/processed/payloads_clean.csv")
    ap.add_argument("--budget", type=int, default=30)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=80)
    args = ap.parse_args()

    corpus = pd.read_csv(args.corpus)
    session = init_session(scope=default_scope(), corpus=corpus, target=MockTarget())
    planner = get_planner()
    app = build_graph(planner, ssvc_policy=default_policy())

    init_state = {
        "host": args.host, "port": args.port, "surfaces": [], "surface_idx": 0,
        "tried_idx": {}, "budget_remaining": args.budget, "plan": None,
        "gov_allowed": False, "response": {}, "results": [],
    }
    final_state = app.invoke(init_state)

    results = pd.DataFrame(final_state["results"])
    tested = results[results["status"] == "TESTED"] if len(results) else results
    blocked = results[results["status"] == "BLOCKED"] if len(results) else results

    print(f"\nPlanner used   : {planner.name}")
    print(f"Total actions  : {len(results)}")
    print(f"Tested         : {len(tested)}  |  Blocked by gate: {len(blocked)}")
    if len(tested):
        print(f"Vulnerable     : {int(tested['vulnerable'].sum())} / {len(tested)}")
        print("\nBy class:")
        print(tested.groupby("attack_class")["vulnerable"].agg(["sum", "count"])
              .rename(columns={"sum": "found", "count": "tested"}))

    print(f"\nAudit log summary: {session.audit.summary()}")


if __name__ == "__main__":
    main()
