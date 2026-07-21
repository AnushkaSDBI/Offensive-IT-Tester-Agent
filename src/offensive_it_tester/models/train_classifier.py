"""
Train the 5-class attack-type router (SQLi / XSS / CSRF / SSRF / CmdInj).

This is the same pipeline trained inside notebooks/week3_final_agent.ipynb
(Section 5.2-5.4), extracted here as a standalone, reproducible script so the model
can be retrained outside a notebook -- e.g. in CI, or after the corpus changes.

Usage:
    python -m offensive_it_tester.models.train_classifier \\
        --corpus data/processed/payloads_clean.csv \\
        --out-dir models/

Leakage guards (see the project documentation, Section 5.1.5, for the full rationale):
`id`, `severity`, `context`, and `type` are never used as features -- only `payload`
text. Exact-duplicate payloads were already removed upstream (notebooks/week1), so no
duplicate can straddle the train/hold-out split.
"""
import argparse
import pathlib

import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

CLASS_ORDER = ["SQLi", "XSS", "CSRF", "SSRF", "CmdInj"]


def train(corpus_path: str, out_dir: str, random_state: int = 42) -> dict:
    df = pd.read_csv(corpus_path)
    if "payload" not in df.columns or "attack_class" not in df.columns:
        raise ValueError(
            f"{corpus_path} must have 'payload' and 'attack_class' columns; "
            f"got {list(df.columns)}"
        )

    label_encoder = LabelEncoder()
    label_encoder.fit(CLASS_ORDER)  # fixed order, so encoded labels are stable across runs
    y_enc = label_encoder.transform(df["attack_class"])

    X_train, X_test, y_train, y_test = train_test_split(
        df["payload"].astype(str), y_enc, test_size=0.2,
        stratify=y_enc, random_state=random_state,
    )

    pipe = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), max_features=3000)),
        ("clf", GradientBoostingClassifier(n_estimators=200, random_state=random_state)),
    ])
    pipe.fit(X_train, y_train)
    y_pred = pipe.predict(X_test)

    report = classification_report(y_test, y_pred, target_names=CLASS_ORDER)
    cm = confusion_matrix(y_test, y_pred)
    print("Classification report (20% hold-out):")
    print(report)
    print("Confusion matrix:")
    print(cm)

    out = pathlib.Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipe, out / "best_pipe.joblib")
    joblib.dump(label_encoder, out / "label_encoder.joblib")
    print(f"\nSaved {out / 'best_pipe.joblib'} and {out / 'label_encoder.joblib'}")

    return {"pipe": pipe, "label_encoder": label_encoder, "report": report, "confusion_matrix": cm}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--corpus", default="data/processed/payloads_clean.csv")
    ap.add_argument("--out-dir", default="models")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()
    train(args.corpus, args.out_dir, args.seed)


if __name__ == "__main__":
    main()
