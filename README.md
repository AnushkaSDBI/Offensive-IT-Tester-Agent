# Offensive IT-Tester: a constrained, lab-scoped vulnerability detection agent

> Responsible AI and Data Ethics, SRH Heidelberg. Author: Anushka Sawant.
> (Rename the project if you like. The one requirement is that the name is yours, not borrowed.)

An AI-assisted web-application vulnerability **detection** agent. It takes an authorized
lab target, uses an agent to select attack payloads from a fixed labelled dataset, tests
each input point through two safety gates, confirms findings **non-destructively**, and
produces an audited, redacted report.

The offensive capability is the small part. The graded contribution is holding that
capability inside a hard authorization boundary and **measuring** whether it stays there.
Where most work in this space maximises exploitation, this project maximises containment
and reports the numbers to prove it.

> **Scope and safety.** The agent runs only against targets on an explicit allowlist,
> in practice a deliberately vulnerable app hosted by us (OWASP Juice Shop or DVWA) in an
> isolated environment. It is built so it cannot be pointed at an arbitrary third-party
> site. This keeps the project inside German criminal law (StGB §202a/§202b/§202c and
> §303a/§303b), GDPR, and the EU AI Act. This is a detection tool, not an exploitation
> tool, and it never runs real destructive operations.

---

## 1. What the data is

`WEB_APPLICATION_PAYLOADS.jsonl` is a labelled corpus of web-application attack strings.
It is ammunition, not a target: it contains no vulnerable code and no traffic, only
payloads with metadata (`id`, `payload`, `context`, `type`, `severity`, `description`,
and one of `example_query` or `example_usage`).

The raw file ships as a single JSON array despite the `.jsonl` extension and does not
parse out of the box. The loader repairs four defects (non-breaking spaces, missing
commas between objects, trailing commas, one invalid `\x` escape) before parsing.

## 2. Data analysis findings

Full analysis in `notebooks/Week1_Payload_Analysis.ipynb`. The decisions that shape the
build:

1. **Five classes, not three.** The brief assumed SQLi, XSS and CmdInj. The corpus also
   contains CSRF and SSRF. Raw counts are 100 per class (500 rows). After dropping the one
   empty payload and deduplicating on the exact string, **455 unique payloads** remain,
   unevenly split because duplicates concentrated in SSRF and CmdInj:

   | Class  | Unique payloads |
   |--------|-----------------|
   | XSS    | 100             |
   | CSRF   | 95              |
   | CmdInj | 88              |
   | SQLi   | 87              |
   | SSRF   | 85              |

2. **Severity labels are not trustworthy.** All 100 XSS rows are labelled `high`, which is
   an annotation artifact. Overall the split is roughly 52 percent high, 30 percent medium,
   15 percent critical, 2 percent low, with critical concentrated in SSRF and CmdInj. Use
   `severity` as a coarse tag only.

3. **Character signatures separate the classes almost perfectly.** SQLi leans on `'` and
   `--`, XSS on `<` `>`, CmdInj on `; | &`, SSRF on `/` alone, CSRF on everything because it
   is full HTML. This gives a cheap pre-filter and an honest baseline to compare any learned
   model against.

4. **Context needs normalising before it can drive selection.** There are ~245 distinct
   free-text `context` values, most with very few payloads and heavy overlap in meaning
   ("User input", "User input field", "Search input" are the same door). Normalising these
   into a small set of injection-point buckets is the highest-priority data-prep task, and
   it unblocks payload selection and the coverage matrix.

5. **The governance gate cannot trust severity labels.** Around 64 payloads are destructive
   in effect, and roughly 30 of them are not labelled high or critical. The gate must
   pattern-scan the payload text, not just read the severity field.

6. **The arsenal is effectively smaller than 455.** Beyond exact duplicates there are many
   near-duplicate pairs (payloads differing only by a counter, near-identical CSRF forms).
   Trimming these saves request budget and reduces DoS risk.

7. **No benign class.** The dataset is attack-only, so the detection layer has no "normal
   response" baseline to calibrate against. This is documented as a limitation in the model
   card, and it is why detection uses per-class proof rather than a single learned
   normal-versus-attack boundary.

## 3. Architecture

Data flows down through the components, results come back up. The two gates are the
responsible-AI control points, and the authorization gate is built first, before any
payload code exists.
```
graph TD
    %% Styling
    classDef operator fill:#f9f,stroke:#333,stroke-width:2px;
    classDef policy fill:#ff9,stroke:#333,stroke-width:2px;
    classDef router fill:#bbf,stroke:#333,stroke-width:1px;
    classDef execution fill:#fbb,stroke:#333,stroke-width:2px;
    classDef analyzer fill:#dfd,stroke:#333,stroke-width:1px;
    classDef audit fill:#ddd,stroke:#333,stroke-width:1px;

    %% Elements
    Op[HUMAN OPERATOR]:::operator --> |Scope + Written Authorisation| Gate[Authorisation and Policy Gate<br>allowlist, limits, test window, kill switch]:::policy
    Gate --> Mapper[Target Context Mapper]:::policy
    
    Mapper --> Router[Rule/ML Payload Router<br>transparent baseline]:::router
    Mapper --> Planner[AI/LLM Planner<br>structured recommendation only]:::router
    
    Router --> Registry[Approved Template Registry]:::policy
    Planner --> Registry
    
    Registry --> Check[Risk Check / Human Approval]:::policy
    Check --> Executor[Sandboxed Request Executor]:::execution
    
    Executor --> A1[SQLi/XSS Analyzer]:::analyzer
    Executor --> A2[CSRF Analyzer]:::analyzer
    Executor --> A3[SSRF Canary Correlator]:::analyzer
    Executor --> A4[CmdInj Canary Analyzer]:::analyzer
    
    A1 --> Engine[Evidence and Confidence Engine]:::audit
    A2 --> Engine
    A3 --> Engine
    A4 --> Engine
    
    Engine --> Report[Risk Scoring + Remediation Report]:::audit
    Report --> Store[Immutable Audit Event Store]:::audit
```   

```
Authorized target URL
        |
        v
[ Scope gate ]          reject out-of-scope, hard allowlist check
        |
        v
[ Recon ]               enumerate injection points (forms, params, headers)
        |
        v
[ Planner (agent) ]  <--+   selects a payload template for each point
        |               |   the LLM proposes, it never invents free payloads
        v               |
[ Governance gate ]     |   destructive-pattern scan, rate limit, human approval
        |               |   loops per payload
        v               |
[ Detect ]  ------------+   non-destructive proof, per class
        |
        v
[ Audit log + Report ]  immutable trail, findings, PII redacted
```

The detection layer is five small class-specific checkers, not one function:

| Class  | Non-destructive proof |
|--------|-----------------------|
| SQLi   | error-string and boolean differential; for blind-time, one short capped SLEEP and a latency check |
| XSS    | reflection check: is the payload returned unescaped in the response HTML |
| CSRF   | request-acceptance check: does the lab accept a forged request lacking a valid anti-CSRF token |
| SSRF   | canary callback: point the payload at a listener we control, detection is the server calling back |
| CmdInj | benign echo canary: inject a command that echoes a random token, detection is the token appearing in output |

The role of the ML model: because payloads arrive pre-labelled, the model does **not**
classify payloads. Its job is response analysis, deciding whether a target's response
indicates a real vulnerability. This is recorded in the model card.

## 4. Repository layout

```
offensive-it-tester/
├── README.md
├── requirements.txt
├── main.py                     # entry point: authorized URL in, audited report out
├── config/                     # safety rules stored as data, not buried in code
│   ├── allowlist.yaml          # authorized lab targets, the scope firewall
│   ├── limits.yaml             # rate limits, timeouts, sleep caps
│   └── gate_rules.yaml         # destructive-pattern rules and severity policy
├── data/
│   ├── raw/                    # untouched Kaggle file
│   ├── clean/                  # payloads_clean.csv, 455 unique rows
│   └── contexts.yaml           # normalised injection-point buckets
├── notebooks/
│   └── Week1_Payload_Analysis.ipynb
├── src/
│   ├── scope/                  # authorization gate
│   ├── recon/                  # injection-point discovery
│   ├── planner/                # agent, payload selection
│   ├── governance/             # governance gate, destructive scan, rate limiting
│   ├── detect/                 # five non-destructive checkers
│   ├── audit/                  # immutable structured run log
│   └── report/                 # report generation and PII redaction
├── eval/                       # the differentiator: measured responsibility
│   ├── ground_truth.yaml       # Juice Shop challenge to payload-class mapping
│   ├── detection_eval.py       # precision and recall against the challenge list
│   └── guardrail_eval.py       # scope-enforcement rate and prompt-injection resistance
├── docs/
│   ├── threat_model.md         # abuse cases of the tool itself, with mitigations
│   ├── regulatory_mapping.md   # EU AI Act, GDPR, StGB, OWASP, ISO 42001, NIST AI RMF
│   └── model_card.md           # response-analysis model, limitations, benign-class gap
└── tests/                      # pytest, one module per src layer
```

## 5. Evaluation (the part that earns the Performance and Responsibility marks)

Two kinds of number, both reported honestly including failures.

**Detection quality.** Precision and recall against OWASP Juice Shop's official challenge
list, which is a published answer key of what is vulnerable and how. See
`eval/detection_eval.py`.

**Guardrail strength.** This is what separates the project from prior work.
- *Scope-enforcement rate*: the fraction of deliberately out-of-scope requests the agent
  refuses. Target 100 percent.
- *Prompt-injection resistance*: the fraction of adversarial target pages (OWASP LLM01
  style) that fail to divert the agent to an off-list action.

See `eval/guardrail_eval.py`.

## 6. Related work

The field is active and this project is positioned against it deliberately.

- **PentestGPT** (Deng et al., USENIX Security 2024, arXiv:2308.06782): the reference
  LLM pentest assistant, three cooperating modules with a human in the loop.
- **Fang et al. (2024)**: LLM agents autonomously hacking websites across the same classes
  this dataset covers (arXiv:2402.06664), reaching about 87 percent on described one-day
  CVEs (arXiv:2404.08144), and agent teams on zero-day targets (arXiv:2406.01637).
- **PentestAgent** (arXiv:2411.05185): multi-agent recon, planning and execution with RAG.
- **CVE-Bench** (arXiv:2503.17332): a benchmark for agents exploiting real web-app CVEs.
- **"Are We There Yet?"** (arXiv:2510.14700): a skeptical evaluation of where these agents
  fail.

Every one of these optimises attack success. This project measures containment instead.
That is the gap it occupies.

## 7. Regulatory and ethics mapping

Mapped against the EU AI Act (Regulation 2024/1689, most likely minimal or limited risk
here, classification documented), GDPR (data minimisation, PII redaction in logs), German
criminal law (StGB §202a/§202b/§202c and §303a/§303b, the dual-use tools provision), OWASP
Top 10 for LLM Applications 2025, MITRE ATLAS mitigations, NIST AI RMF, and ISO/IEC 42001.
Full mapping in `docs/regulatory_mapping.md` and in the notebook.

## 8. Data provenance

The corpus was obtained from Kaggle with no clearly stated original source or licence in
the file. It is treated as unknown licence: the source URL and access date are recorded,
the raw file is not redistributed until the licence is confirmed, and an equivalent corpus
can be regenerated from permissively licensed public sources (SecLists,
PayloadsAllTheThings) if needed. The individual payload strings are common public
knowledge; the licensing question concerns the compilation.

## 9. Running it

```bash
# 1. stand up the lab target
docker run --rm -p 3000:3000 bkimminich/juice-shop

# 2. install
pip install -r requirements.txt

# 3. confirm the target is on the allowlist, then run
python main.py --target http://localhost:3000
```

The agent refuses to start against any target not present in `config/allowlist.yaml`.

## 10. Limitations

Curated string corpus, not live traffic. No benign class, so no learned normal-response
baseline. Severity labels are unreliable. Context values require normalisation. Findings
describe the payloads and the agent's behaviour, not any production system's exposure.
This is coursework, not a production security tool, and it is not legal advice.

## License

Code under MIT (see `LICENSE`). The payload dataset is third-party and is not relicensed
here; see section 8.
