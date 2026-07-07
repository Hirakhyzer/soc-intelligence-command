"""Hash-chained laboratory audit ledger for experiment traceability."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


def append_record(path: str | Path, record: dict[str, Any]) -> dict[str, Any]:
    """Append one JSONL record linked to the preceding record hash."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    previous_hash = None
    if destination.exists():
        lines = [line for line in destination.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            previous_hash = json.loads(lines[-1])["record_hash"]
    enriched = {**record, "previous_hash": previous_hash}
    enriched["record_hash"] = _hash(enriched)
    with destination.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(enriched, sort_keys=True, default=str) + "\n")
    return enriched


def verify_ledger(path: str | Path) -> dict[str, Any]:
    """Verify integrity and continuity of a JSONL audit ledger."""
    destination = Path(path)
    previous_hash = None
    count = 0
    for line_number, line in enumerate(destination.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        record = json.loads(line)
        stored = record.pop("record_hash", None)
        if record.get("previous_hash") != previous_hash:
            return {"valid": False, "line": line_number, "reason": "previous hash mismatch", "records": count}
        if stored != _hash(record):
            return {"valid": False, "line": line_number, "reason": "record hash mismatch", "records": count}
        previous_hash = stored
        count += 1
    return {"valid": True, "records": count, "final_hash": previous_hash}


def _hash(record: dict[str, Any]) -> str:
    return hashlib.sha256(json.dumps(record, sort_keys=True, default=str).encode()).hexdigest()
