# Data

## `raw/WEB_APPLICATION_PAYLOADS.jsonl`

The original payload corpus (500 rows, 5 classes: SQLi, XSS, CSRF, SSRF, CmdInj). The
file ships with a `.jsonl` extension but is actually a single pretty-printed JSON array
with four formatting defects (non-breaking spaces, missing/trailing commas, one invalid
escape) — see `notebooks/week1_data_analysis.ipynb`, Section 1, for the defensive
loader that repairs them.

**Provenance / licensing:** obtained from a third-party Kaggle upload with no clearly
stated original source or license. Treated as **unknown license** — recorded here, not
redistributed with an implied license, and used for non-commercial coursework only. If
you need a clean-license equivalent, regenerate an equivalent corpus from
[SecLists](https://github.com/danielmiessler/SecLists) (MIT licensed) or
[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings).

## `processed/payloads_clean.csv`

The deduplicated output of Week 1's cleaning (455 unique payloads, one empty row and
44 exact duplicates removed). Columns: `id, attack_class, type, severity, context,
payload_hash, payload`. This is what `offensive_it_tester.models.train_classifier`
and the agent's corpus both train/plan against.

## `processed/fwaf_clean.csv`

~104k real request strings (44.7k attack, 59.9k benign), fetched directly from the
[FWAF project](https://github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall)
(the source the Kaggle `fwaf-dataset` is built from — fetched here directly since
Kaggle requires per-user credentials). Used as the training set for the binary
attack/benign pre-filter.

## `processed/csic_clean.csv`

~16.6k real HTTP requests (9.3k normal, 7.3k anomalous), parsed from the original
[HTTP DATASET CSIC 2010](https://www.isi.csic.es/en/) request-line + body format.
Used as a **held-out, never-trained-on** cross-source generalisation test for the
binary pre-filter — see notebooks/week2 for the honest finding (F1 0.99 in-distribution
→ 0.61 out-of-distribution).

Neither FWAF's repository nor the CSIC 2010 release states an explicit open-source
license. Both are long-standing, widely cited public research datasets; used here for
non-commercial coursework only.
