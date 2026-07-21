"""
Tamper-evident, hash-chained audit log.

Every entry is chained to the previous via sha256(prev_hash + canonical(record)).
Any deletion, modification, or reordering breaks the chain, which verify() detects.
This is the same integrity mechanism used in blockchain ledgers and the aegissec
audit-continuity module, adapted for an in-memory agent session.

Inspired by RADE's hash-chained audit and aegissec-fedops' AuditContinuity pattern,
but independently implemented against our own AuditLog interface.
"""
import hashlib
import json
import uuid
from collections import Counter
from datetime import datetime
from typing import Any, Dict, List

GENESIS_HASH = "0" * 64


def _canonical(record: Dict[str, Any]) -> str:
    """Deterministic serialization: sorted keys, compact separators, no NaN."""
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def _chain_hash(prev_hash: str, canonical_record: str) -> str:
    return hashlib.sha256((prev_hash + canonical_record).encode("utf-8")).hexdigest()


class AuditLog:
    """Append-only, hash-chained audit log.

    Each entry stores the hash of (previous_hash + canonical(this_entry)),
    forming an integrity chain. verify() walks the chain and returns
    (valid: bool, findings: list[str]).
    """

    def __init__(self, scope_id: str):
        self.scope_id = scope_id
        self.entries: List[Dict[str, Any]] = []
        self._prev_hash: str = GENESIS_HASH

    def log(self, action: str, details: dict, result: str) -> dict:
        entry = {
            "timestamp": datetime.now().isoformat(),
            "scope_id": self.scope_id,
            "action": action,
            "details": details,
            "result": result,
            "entry_id": str(uuid.uuid4())[:8],
            "sequence": len(self.entries) + 1,
        }
        canonical = _canonical(entry)
        entry_hash = _chain_hash(self._prev_hash, canonical)
        entry["prev_hash"] = self._prev_hash
        entry["entry_hash"] = entry_hash
        self._prev_hash = entry_hash
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple:
        """Walk the full chain. Returns (valid: bool, findings: list[str])."""
        findings = []
        expected_prev = GENESIS_HASH
        for i, entry in enumerate(self.entries):
            stored_hash = entry.get("entry_hash", "")
            stored_prev = entry.get("prev_hash", "")
            if stored_prev != expected_prev:
                findings.append(f"entry {i}: prev_hash mismatch (chain broken)")
            record_without_hashes = {k: v for k, v in entry.items()
                                     if k not in ("prev_hash", "entry_hash")}
            expected_hash = _chain_hash(stored_prev, _canonical(record_without_hashes))
            if stored_hash != expected_hash:
                findings.append(f"entry {i}: entry_hash mismatch (record tampered)")
            expected_prev = stored_hash
        return (len(findings) == 0, findings)

    def summary(self) -> str:
        if not self.entries:
            return "No entries."
        valid, findings = self.verify()
        integrity = "INTACT" if valid else f"BROKEN ({len(findings)} finding(s))"
        actions = Counter(e["action"] for e in self.entries)
        return (f"Entries: {len(self.entries)} | Chain: {integrity} | "
                f"Actions: {dict(actions)}")
