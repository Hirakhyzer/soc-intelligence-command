"""Canonical event schema and defensive normalization routines."""

from __future__ import annotations

import hashlib
import json
from typing import Any

import pandas as pd


CANONICAL_COLUMNS = (
    "event_id", "timestamp", "source_type", "event_type", "action", "status",
    "user", "host", "src_ip", "dst_ip", "dst_host", "process_name",
    "parent_process", "domain", "asset_criticality", "is_malicious", "scenario",
)


def normalize_events(events: pd.DataFrame) -> pd.DataFrame:
    """Normalize events to a minimal SOC schema without inventing missing evidence.

    Missing optional fields are represented as empty strings. `timestamp` must be
    parseable. If `event_id` is absent, a stable hash is created from row content.
    """
    normalized = events.copy()
    if "timestamp" not in normalized.columns:
        raise KeyError("Every SOC event requires a timestamp column.")
    normalized["timestamp"] = pd.to_datetime(normalized["timestamp"], errors="raise", utc=True)
    for column in CANONICAL_COLUMNS:
        if column not in normalized.columns:
            if column == "is_malicious":
                normalized[column] = 0
            elif column == "scenario":
                normalized[column] = "benign"
            elif column == "asset_criticality":
                normalized[column] = "medium"
            else:
                normalized[column] = ""
    if (normalized["event_id"] == "").any():
        normalized.loc[normalized["event_id"] == "", "event_id"] = normalized.loc[
            normalized["event_id"] == ""
        ].apply(_event_hash, axis=1)
    normalized["asset_criticality"] = normalized["asset_criticality"].str.lower().replace("", "medium")
    normalized["is_malicious"] = normalized["is_malicious"].astype(int)
    return normalized.loc[:, CANONICAL_COLUMNS].sort_values("timestamp").reset_index(drop=True)


def _event_hash(row: pd.Series) -> str:
    payload: dict[str, Any] = {key: str(row.get(key, "")) for key in row.index}
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:20]
