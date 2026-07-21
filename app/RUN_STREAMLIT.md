# Running the Streamlit interface

This is a bonus interactive layer on top of the notebooks (Week 3/4 goal: "think about
how users will interact with your system"). The graded, complete deliverable is
notebooks/week3_final_agent.ipynb; this is the operator-console demo on top, built on
the exact same tested `offensive_it_tester.core` package.

## One-time setup (from the repo root)

```bash
pip install -e ".[app]"
```

This needs the trained model and processed data already present:
`models/best_pipe.joblib`, `models/label_encoder.joblib`,
`data/processed/payloads_clean.csv` — all included in this repo. To regenerate them:

```bash
python -m offensive_it_tester.models.train_classifier
```

## Run it (from the repo root, not from inside app/)

```bash
streamlit run app/app.py
```

Opens at http://localhost:8501

## What it demonstrates

- **Scan configuration** (sidebar): pick an authorized target, attack classes, run a scan.
- **Live scope-gate probe**: type an unauthorized host and watch it get blocked in real time.
- **Human review queue**: destructive-flagged and medium-confidence findings wait here
  for an explicit Approve/Deny click — the human-in-the-loop principle made
  clickable, not just a diagram box.
- **Results table + findings-by-class chart.**
- **Searchable audit log**, the same append-only record `offensive_it_tester.core.AuditLog` produces.
- **Live classifier demo**: type a payload, see the real trained model's routing decision.

## Verification note

This app is tested with Streamlit's own `AppTest` framework (executes the script
in-process, not just an HTTP check): initial load, the Run Scan button, and the
Approve button are all clicked programmatically and confirmed to run with zero
exceptions as part of this repo's own checks.
