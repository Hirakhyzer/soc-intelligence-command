"""Synthetic-laboratory alert-quality metrics.

Metrics here use synthetic event labels only. They are useful for regression tests
and detector comparison, but are not a substitute for real SOC validation.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score


def synthetic_alert_metrics(events: pd.DataFrame, alerts: pd.DataFrame) -> dict[str, float | int | None]:
    """Calculate event-linked precision/recall and alert-volume reduction."""
    detected_ids = set(alerts["event_id"].tolist()) if not alerts.empty else set()
    truth = events[["event_id", "is_malicious"]].copy()
    truth["detected"] = truth["event_id"].isin(detected_ids).astype(int)
    y_true = truth["is_malicious"].to_numpy(dtype=int)
    y_pred = truth["detected"].to_numpy(dtype=int)
    precision = float(precision_score(y_true, y_pred, zero_division=0))
    recall = float(recall_score(y_true, y_pred, zero_division=0))
    volume_reduction = 1.0 - (len(alerts) / max(len(events), 1))
    mttd_minutes = _mean_time_to_detect(events, alerts)
    return {
        "event_count": int(len(events)),
        "alert_count": int(len(alerts)),
        "synthetic_precision": precision,
        "synthetic_recall": recall,
        "alert_volume_reduction": float(volume_reduction),
        "synthetic_mttd_minutes": mttd_minutes,
    }


def _mean_time_to_detect(events: pd.DataFrame, alerts: pd.DataFrame) -> float | None:
    if alerts.empty:
        return None
    labeled = events.loc[events["is_malicious"] == 1]
    delays: list[float] = []
    for scenario, group in labeled.groupby("scenario"):
        first_event = pd.to_datetime(group["timestamp"], utc=True).min()
        linked = alerts.loc[alerts["scenario"] == scenario]
        if linked.empty:
            continue
        first_alert = pd.to_datetime(linked["timestamp"], utc=True).min()
        delays.append(max(0.0, (first_alert - first_event).total_seconds() / 60.0))
    return float(np.mean(delays)) if delays else None
