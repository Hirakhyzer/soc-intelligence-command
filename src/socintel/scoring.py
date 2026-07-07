"""Transparent alert-priority scoring for analyst triage."""

from __future__ import annotations

import numpy as np
import pandas as pd


SEVERITY_WEIGHT = {"low": 0.25, "medium": 0.50, "high": 0.75, "critical": 1.00}
CRITICALITY_WEIGHT = {"low": 0.20, "medium": 0.45, "high": 0.70, "critical": 1.00}


def prioritize_alerts(alerts: pd.DataFrame, reference_time: pd.Timestamp | None = None) -> pd.DataFrame:
    """Score alerts using severity, confidence, asset criticality, anomaly, and recency.

    The score is explainable and intended to rank analyst queues, not to justify
    an automated destructive response.
    """
    output = alerts.copy()
    if output.empty:
        output["risk_score"] = pd.Series(dtype=float)
        output["priority"] = pd.Series(dtype=str)
        return output
    timestamp = pd.to_datetime(output["timestamp"], utc=True)
    now = reference_time or timestamp.max()
    age_hours = (now - timestamp).dt.total_seconds().clip(lower=0) / 3600.0
    recency = np.exp(-age_hours / 24.0)
    severity = output["severity"].map(SEVERITY_WEIGHT).fillna(0.5)
    criticality = output["asset_criticality"].map(CRITICALITY_WEIGHT).fillna(0.45)
    confidence = output["confidence"].clip(0.0, 1.0)
    anomaly = output.get("anomaly_score", pd.Series(0.0, index=output.index)).clip(lower=0.0)
    anomaly_scaled = anomaly / max(float(anomaly.max()), 1e-8)
    output["risk_score"] = (100.0 * (0.32 * severity + 0.25 * confidence + 0.20 * criticality + 0.13 * anomaly_scaled + 0.10 * recency)).round(2)
    output["priority"] = pd.cut(output["risk_score"], bins=[-1, 40, 60, 80, 101], labels=["low", "medium", "high", "critical"]).astype(str)
    output["priority_rationale"] = (
        "severity=" + output["severity"].astype(str)
        + "; confidence=" + output["confidence"].round(2).astype(str)
        + "; asset=" + output["asset_criticality"].astype(str)
        + "; anomaly=" + output.get("anomaly_flag", pd.Series(0, index=output.index)).astype(str)
    )
    return output.sort_values(["risk_score", "timestamp"], ascending=[False, True]).reset_index(drop=True)
