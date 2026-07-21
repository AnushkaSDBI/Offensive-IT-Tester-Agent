# Notebooks

The professor's deliverable format is the notebook, so each week's graded work is kept
here exactly as submitted (each is self-contained and independently runnable — see the
main README for how to get the data/models they need alongside them). `src/` is a
*separate*, later decomposition of the same tested logic into an importable package
(see the main README's "Two ways to use this project" section) — it does not replace
these notebooks, it exists so the code is usable outside a notebook too (imports,
tests, CI, the Streamlit app).

## week1_data_analysis.ipynb

Week 1 goals: analyze the data, derive a project plan, propose an architecture, do a
regulatory analysis. Covers: defensive JSONL loading, class balance and severity bias,
character-signature analysis (the key finding — each attack class has a near-distinct
fingerprint), context-coverage normalisation and its Gini coefficient, near-duplicate
detection, and the German/EU regulatory grounding (StGB §202c, EU AI Act).

## week2_baseline_and_agent.ipynb

Week 2 goals: build a baseline model, risk analysis, fairness analysis. Also carries
forward Week 1's content (so it is self-contained) and goes further: the 5-class payload
classifier with a documented Dummy-classifier floor, the FWAF/CSIC cross-source
generalisation check, the first working agent loop (scope gate, five detectors, mock
target), then its upgrade to a tool-calling LangGraph agent with an LLM planner and an
honest deterministic fallback, a risk register mapped to NIST AI RMF / MITRE ATLAS /
OWASP, and fairness analysis (per-class F1 gap, context-coverage Gini, severity-label
entropy).

## week3_final_agent.ipynb

**The complete, final graded deliverable** (Week 3/4 goals: analyze the model, XAI,
automated weakness tests with 80%+ coverage, an interface, plus the final packaging).
Everything in weeks 1-2 above, plus:

- Model explainability: global + per-class n-gram importance, character-level
  attribution, classifier metamorphic-robustness testing.
- An oracle-evidence visualization explaining the *agent's* verdicts, not just the
  classifier's.
- An automated weakness-detection suite that **found two real bugs** in the original
  detectors (SSRF over-breadth, CmdInj false positives), documents them, fixes them,
  and re-runs the same suite green — with a before/after comparison.
- The extracted `agent_core.py` module and its 100%-statement-coverage test suite
  (the ancestor of `src/offensive_it_tester/core/`).
- An audit/log dashboard (inline + exportable standalone HTML).
- The on-prem Qwen planner (privacy-first resolution order) and the Streamlit
  operator-console interface (`app/app.py`).

## Running any notebook

Each notebook expects, in the **same folder as the notebook**:
`WEB_APPLICATION_PAYLOADS.jsonl`, `payloads_clean.csv`, `fwaf_clean.csv`,
`csic_clean.csv`. Copy them from `data/raw/` and `data/processed/`, e.g. from the repo
root:

```bash
cp data/raw/*.jsonl data/processed/*.csv notebooks/
jupyter notebook notebooks/week3_final_agent.ipynb
```

Then **Kernel → Restart & Run All**. Some cells `%%writefile` a copy of `agent_core.py`
and `test_agent_core.py` into the notebook's own folder — that is the historical,
in-notebook route to the same logic now organised as `src/offensive_it_tester/`.
