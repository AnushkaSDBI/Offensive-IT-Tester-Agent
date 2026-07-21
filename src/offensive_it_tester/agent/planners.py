"""
Planning module: decides which payload to try next at a given target surface.

Privacy-first resolution order (see the project documentation, Section 9, for the
full rationale): a local, on-prem Qwen model (via Ollama) is tried first, so payload
and target data never leave the machine. A cloud model is used only if explicitly
configured and is flagged as sending data off-machine. A deterministic fallback keeps
the agent fully runnable with no LLM credentials at all -- this is the path exercised
by tests/test_agent_core.py and by CI.

Every planner shares one guardrail: it selects an INDEX into the already-reviewed
payload corpus. None of them free-generate payload text.
"""
import json
import os

import pandas as pd


class LLMPlanner:
    """Given a target surface and the untried corpus, return one plan:
    {'attack_class', 'payload', 'corpus_index', 'rationale'}, or None if nothing fits."""

    name = "base"

    def plan(self, surface: dict, corpus: pd.DataFrame, tried: set):
        raise NotImplementedError


class AnthropicPlanner(LLMPlanner):
    """Cloud LLM planner (opt-in). Presents up to 20 untried, class-matched corpus
    entries as a numbered menu and asks the model to pick one by index."""

    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-5"):
        import anthropic  # local import: only required if this planner is used

        self.client = anthropic.Anthropic()
        self.model = model

    def plan(self, surface, corpus, tried):
        pool = corpus[corpus["attack_class"].isin(surface["expected_vulns"])]
        pool = pool[~pool.index.isin(tried)]
        rows = list(pool.head(20).itertuples())
        if not rows:
            return None
        menu = "\n".join(f"{i}: [{r.attack_class}] {str(r.payload)[:60]}" for i, r in enumerate(rows))
        prompt = (
            "You are the planning module of an authorized web-security test agent.\n"
            f"Target surface: {surface['method']} {surface['path']} (parameter: {surface['parameter']})\n"
            f"Expected vulnerability classes for this surface: {surface['expected_vulns']}\n\n"
            "Choose exactly ONE payload from this reviewed template registry by index. "
            "Do not invent a new payload.\n\n"
            f"{menu}\n\n"
            'Respond as JSON only: {"index": <int>, "rationale": "<one sentence>"}'
        )
        resp = self.client.messages.create(
            model=self.model, max_tokens=200, messages=[{"role": "user", "content": prompt}]
        )
        text = resp.content[0].text
        data = json.loads(text[text.find("{"):text.rfind("}") + 1])
        row = rows[data["index"]]
        return {
            "attack_class": row.attack_class, "payload": row.payload,
            "corpus_index": row.Index, "rationale": data.get("rationale", ""),
        }


class QwenPlanner(LLMPlanner):
    """On-prem planner using a LOCAL Qwen model served by Ollama
    (http://localhost:11434 by default). No payload or target data leaves the
    machine. This is the default planner -- see `get_planner()`."""

    name = "qwen-local (ollama)"

    def __init__(self, model: str = "qwen2.5:7b-instruct", host: str = "http://localhost:11434"):
        import requests  # local import: only required if this planner is used

        self.requests = requests
        self.model = model
        self.host = host
        # fail fast if Ollama / the model isn't actually present, so get_planner() can fall back
        r = self.requests.get(f"{host}/api/tags", timeout=3)
        tags = [m["name"] for m in r.json().get("models", [])]
        if not any(self.model.split(":")[0] in t for t in tags):
            raise RuntimeError(f"Qwen model '{self.model}' not pulled in Ollama. Run: ollama pull {self.model}")

    def plan(self, surface, corpus, tried):
        pool = corpus[corpus["attack_class"].isin(surface["expected_vulns"])]
        pool = pool[~pool.index.isin(tried)]
        rows = list(pool.head(20).itertuples())
        if not rows:
            return None
        menu = "\n".join(f"{i}: [{r.attack_class}] {str(r.payload)[:60]}" for i, r in enumerate(rows))
        prompt = (
            "You are the planning module of an authorized web-security test agent.\n"
            f"Target surface: {surface['method']} {surface['path']} (parameter: {surface['parameter']})\n"
            f"Expected vulnerability classes: {surface['expected_vulns']}\n\n"
            "Choose exactly ONE payload from this reviewed registry by index. Do not invent a payload.\n\n"
            f"{menu}\n\n"
            'Respond as JSON only: {"index": <int>, "rationale": "<one sentence>"}'
        )
        resp = self.requests.post(
            f"{self.host}/api/generate", timeout=60,
            json={"model": self.model, "prompt": prompt, "stream": False, "format": "json",
                  "options": {"temperature": 0.2}},
        )
        text = resp.json()["response"]
        data = json.loads(text[text.find("{"):text.rfind("}") + 1])
        row = rows[int(data["index"])]
        return {
            "attack_class": row.attack_class, "payload": row.payload,
            "corpus_index": row.Index, "rationale": data.get("rationale", ""),
        }


class DeterministicPlanner(LLMPlanner):
    """Documented, tested fallback: first untried, class-matched corpus entry,
    round-robin across surfaces. Used automatically when no local Qwen and no cloud
    credentials are available -- this is the path CI and the test suite exercise."""

    name = "deterministic-fallback"

    def plan(self, surface, corpus, tried):
        pool = corpus[corpus["attack_class"].isin(surface["expected_vulns"])]
        pool = pool[~pool.index.isin(tried)]
        if pool.empty:
            return None
        idx = pool.index[0]
        row = pool.loc[idx]
        return {
            "attack_class": row["attack_class"], "payload": row["payload"],
            "corpus_index": idx, "rationale": "fallback: first untried template for this class",
        }


def get_planner() -> LLMPlanner:
    """Privacy-first resolution: local Qwen -> cloud (opt-in) -> deterministic
    fallback. The ordering itself is the data-governance control."""
    try:
        p = QwenPlanner()
        print(f"Planner: {p.name} (local, on-prem -- no data leaves the machine)")
        return p
    except Exception as e:
        print(f"QwenPlanner (local Ollama) unavailable: {e}")

    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            p = AnthropicPlanner()
            print(f"Planner: {p.name} (cloud LLM -- data leaves the machine, see the model card)")
            return p
        except Exception as e:
            print(f"AnthropicPlanner unavailable ({e}); falling back.")

    p = DeterministicPlanner()
    print(
        f"Planner: {p.name} -- no local Qwen and no cloud key available. "
        f"Run `ollama pull qwen2.5:7b-instruct` for on-prem planning; nothing else changes."
    )
    return p
