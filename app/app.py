"""
Offensive IT-Tester -- Streamlit control panel

Bonus interface layer described in Week 3/4 goals ("think about how users will
interact with your system"). This is deliberately a THIN layer: every piece of
security logic (ScopeGate, the five detectors, MockTarget) is imported from
offensive_it_tester.core, the exact package the pytest suite covers at 100%.
Nothing here reimplements or bypasses that logic.

Run with:  streamlit run app.py
Run from the repo root (needs the package installed: `pip install -e .`), and needs
models/best_pipe.joblib, models/label_encoder.joblib, and
data/processed/payloads_clean.csv to already exist (see README "Reproducing results").
"""
import time
import pandas as pd
import streamlit as st
import plotly.express as px

from offensive_it_tester.core import ScopeGate, build_detectors, MockTarget, default_scope

st.set_page_config(page_title="Offensive IT-Tester", layout="wide", page_icon="🛡️")

# ---------------------------------------------------------------- session state
if "audit" not in st.session_state:
    st.session_state.audit = []          # list of dicts, our in-memory audit log
if "results" not in st.session_state:
    st.session_state.results = []        # list of tested/blocked payload results
if "pending_review" not in st.session_state:
    st.session_state.pending_review = [] # payloads a human must approve/deny
if "gate" not in st.session_state:
    st.session_state.gate = ScopeGate(default_scope())
if "target" not in st.session_state:
    st.session_state.target = MockTarget()
if "detectors" not in st.session_state:
    st.session_state.detectors = build_detectors()


def log(action, details, result):
    st.session_state.audit.append({
        "ts": time.strftime("%H:%M:%S"), "action": action, "details": details, "result": result
    })


@st.cache_resource
def load_model():
    import joblib
    try:
        pipe = joblib.load("models/best_pipe.joblib")
        le = joblib.load("models/label_encoder.joblib")
        return pipe, le, True
    except (FileNotFoundError, Exception):
        return None, None, False


@st.cache_data
def load_corpus():
    try:
        return pd.read_csv("data/processed/payloads_clean.csv")
    except FileNotFoundError:
        return pd.DataFrame(columns=["attack_class", "payload"])


best_pipe, label_encoder, model_loaded = load_model()
corpus = load_corpus()
CLASS_ORDER = ["SQLi", "XSS", "CSRF", "SSRF", "CmdInj"]

# ---------------------------------------------------------------- sidebar: scan controls
st.sidebar.title("Scan configuration")

if not model_loaded:
    st.sidebar.warning("models/best_pipe.joblib not found. Run the notebook once (through the "
                       "'Persisting the trained model' cell) so this app can load the "
                       "real trained classifier. The scan itself still works without it, "
                       "the classifier is used for the routing demo, not for detection.")
if corpus.empty:
    st.sidebar.warning("payloads_clean.csv not found in this folder; using no payloads.")

target_host = st.sidebar.selectbox("Target host (authorized allowlist)",
    sorted(st.session_state.gate.scope.authorized_hosts), index=0)
target_port = st.sidebar.selectbox("Target port", sorted(st.session_state.gate.scope.authorized_ports))
selected_classes = st.sidebar.multiselect("Attack classes to test", CLASS_ORDER, default=CLASS_ORDER)
n_per_class = st.sidebar.slider("Payloads per class", 1, 10, 3)

st.sidebar.markdown("---")
st.sidebar.caption("Out-of-scope probe (demonstrates the gate live)")
oos_host = st.sidebar.text_input("Try an unauthorized host", "evil.com")
if st.sidebar.button("Test scope gate against it"):
    allowed, reason = st.session_state.gate.check(oos_host, target_port, "GET", "test")
    log("scope_probe", {"host": oos_host}, reason)
    if allowed:
        st.sidebar.error(f"Unexpectedly ALLOWED ({reason}) -- this would be a real bug.")
    else:
        st.sidebar.success(f"Correctly BLOCKED: {reason}")

run = st.sidebar.button("▶ Run scan", type="primary", width='stretch')

# ---------------------------------------------------------------- header / tiles
st.title("Offensive IT-Tester — Operator Console")
st.caption("Authorized, lab-scoped vulnerability testing agent. Every action below is "
          "logged and gated by the same ScopeGate covered at 100% in the test suite.")
st.info("**EU AI Act Art. 50 disclosure:** When the on-prem Qwen or cloud planner is active, "
        "scan results, payload selection rationale, and report text may contain AI-generated content. "
        "The scope gate, detectors, and audit log are deterministic Python, not AI-generated.",
        icon="📋")

t1, t2, t3, t4 = st.columns(4)
tested = [r for r in st.session_state.results if r["status"] == "TESTED"]
blocked = [r for r in st.session_state.results if r["status"] == "BLOCKED"]
vuln = [r for r in tested if r["vulnerable"]]
t1.metric("Payloads tested", len(tested))
t2.metric("Vulnerable findings", len(vuln))
t3.metric("Blocked by scope gate", len(blocked))
t4.metric("Pending human review", len(st.session_state.pending_review))

# ---------------------------------------------------------------- run the scan
if run:
    st.session_state.results = []
    progress = st.progress(0.0, text="Starting scan...")
    surfaces = [s for s in st.session_state.target.enumerate_surfaces()
               if any(v in selected_classes for v in s["expected_vulns"])]
    total = 0
    for s in surfaces:
        total += min(n_per_class, len(corpus[corpus["attack_class"].isin(s["expected_vulns"])]))
    done = 0

    for surface in surfaces:
        ac_pool = [c for c in surface["expected_vulns"] if c in selected_classes]
        for ac in ac_pool:
            payloads = corpus[corpus["attack_class"] == ac]["payload"].head(n_per_class)
            for payload in payloads:
                allowed, reason = st.session_state.gate.check(
                    target_host, target_port, surface["method"], str(payload))
                log("scope_check", {"path": surface["path"], "class": ac}, reason)
                if not allowed:
                    st.session_state.results.append({
                        "class": ac, "endpoint": surface["path"], "payload": str(payload)[:40],
                        "status": "BLOCKED", "reason": reason, "vulnerable": False, "confidence": "-"})
                    if reason == "destructive":
                        st.session_state.pending_review.append({
                            "class": ac, "endpoint": surface["path"], "payload": str(payload)[:60],
                            "reason": "flagged destructive by scope gate"})
                    done += 1
                    progress.progress(min(done / max(total, 1), 1.0), text=f"{surface['path']} [{ac}]")
                    continue
                st.session_state.gate.record_request()
                resp = st.session_state.target.send_request(
                    surface["path"], surface["method"], surface["parameter"], str(payload), attack_class=ac)
                log("request_sent", {"path": surface["path"], "class": ac}, f"status={resp['status_code']}")
                det = st.session_state.detectors[ac].check(
                    str(payload), resp["body"], resp["status_code"], resp["response_time"])
                log("detection", {"path": surface["path"], "class": ac}, "VULN" if det["vulnerable"] else "safe")
                st.session_state.results.append({
                    "class": ac, "endpoint": surface["path"], "payload": str(payload)[:40],
                    "status": "TESTED", "reason": "-", "vulnerable": det["vulnerable"],
                    "confidence": det["confidence"]})
                if det["confidence"] == "medium":
                    st.session_state.pending_review.append({
                        "class": ac, "endpoint": surface["path"], "payload": str(payload)[:60],
                        "reason": "medium-confidence verdict, needs human confirmation"})
                done += 1
                progress.progress(min(done / max(total, 1), 1.0), text=f"{surface['path']} [{ac}]")
    progress.empty()
    st.rerun()

# ---------------------------------------------------------------- human-in-the-loop review
st.markdown("---")
st.subheader("Human review queue")
st.caption("This is the human-in-the-loop control made clickable: anything the governance "
          "gate flagged as destructive, or the detector is only medium-confidence about, "
          "waits here for a human decision instead of being auto-resolved.")

if not st.session_state.pending_review:
    st.info("Nothing pending review.")
else:
    for i, item in enumerate(list(st.session_state.pending_review)):
        c1, c2, c3, c4 = st.columns([2, 4, 3, 2])
        c1.write(f"**{item['class']}**  `{item['endpoint']}`")
        c2.code(item["payload"], language="text")
        c3.write(item["reason"])
        if c4.button("Approve", key=f"appr_{i}"):
            log("human_review", item, "APPROVED by operator")
            st.session_state.pending_review.pop(i)
            st.rerun()
        if c4.button("Deny", key=f"deny_{i}"):
            log("human_review", item, "DENIED by operator")
            st.session_state.pending_review.pop(i)
            st.rerun()

# ---------------------------------------------------------------- results + charts
st.markdown("---")
left, right = st.columns([3, 2])

with left:
    st.subheader("Scan results")
    if st.session_state.results:
        rdf = pd.DataFrame(st.session_state.results)
        st.dataframe(rdf, width='stretch', height=320)
    else:
        st.info("No scan run yet. Configure the target in the sidebar and click Run scan.")

with right:
    st.subheader("Findings by class")
    if st.session_state.results:
        rdf = pd.DataFrame(st.session_state.results)
        summary = rdf.groupby("class").agg(
            tested=("status", lambda s: (s == "TESTED").sum()),
            vulnerable=("vulnerable", "sum"),
            blocked=("status", lambda s: (s == "BLOCKED").sum()),
        ).reindex(CLASS_ORDER).fillna(0)
        fig = px.bar(summary, barmode="group", labels={"value": "count", "class": ""})
        st.plotly_chart(fig, width='stretch')

# ---------------------------------------------------------------- audit log
st.markdown("---")
st.subheader("Audit log")
st.caption("Every gate decision, request, detection, and human review, in order. "
          "This is the same append-only record the notebook's AuditLog produces.")
if st.session_state.audit:
    adf = pd.DataFrame(st.session_state.audit)
    q = st.text_input("Filter (action / class / result contains...)", "")
    if q:
        mask = adf.astype(str).apply(lambda r: r.str.contains(q, case=False)).any(axis=1)
        adf = adf[mask]
    st.dataframe(adf.sort_index(ascending=False), width='stretch', height=260)
else:
    st.info("Audit log is empty. Run a scan or a scope-gate probe.")

# ---------------------------------------------------------------- classifier demo
st.markdown("---")
st.subheader("Try the payload classifier")
st.caption("EU AI Act Art. 50: the classifier's prediction is a trained ML model output, "
           "not a deterministic rule. The routing decision is AI-generated; the security "
           "verdict (vulnerable/not) comes from the deterministic detectors, not the classifier.")
st.caption("Uses the real best_pipe.joblib trained in the notebook, same model as Section "
          "5. This is the ROUTER only, it does not decide vulnerability, the detectors do.")
sample = st.text_input("Enter a payload to classify", "' OR 1=1--")
if sample and model_loaded:
    pred = label_encoder.inverse_transform(best_pipe.predict([sample]))[0]
    st.success(f"Predicted class: **{pred}**")
elif sample:
    st.warning("Classifier not loaded (best_pipe.joblib missing).")
