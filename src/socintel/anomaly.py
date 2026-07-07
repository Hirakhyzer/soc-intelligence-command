"""Entity-window anomaly evidence for defensive SOC triage."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest


def build_hourly_entity_features(events: pd.DataFrame) -> pd.DataFrame:
    """Aggregate host-hour counts into interpretable anomaly-model inputs."""
    work = events.copy()
    work["hour_bucket"] = pd.to_datetime(work["timestamp"], utc=True).dt.floor("h")
    work["failed_auth"] = ((work["event_type"] == "authentication") & (work["status"] == "failure")).astype(int)
    work["dns_event"] = (work["event_type"] == "dns_query").astype(int)
    work["remote_auth"] = (work["event_type"] == "remote_auth").astype(int)
    work["identity_change"] = (work["event_type"] == "identity_change").astype(int)
    result = work.groupby(["host", "hour_bucket"], dropna=False).agg(
        event_count=("event_id", "count"),
        failed_auth=("failed_auth", "sum"),
        dns_events=("dns_event", "sum"),
        remote_auth_events=("remote_auth", "sum"),
        identity_changes=("identity_change", "sum"),
        distinct_domains=("domain", lambda values: values.replace("", pd.NA).dropna().nunique()),
        asset_criticality=("asset_criticality", "first"),
    ).reset_index()
    return result


def fit_score_anomalies(features: pd.DataFrame, seed: int = 42, baseline_fraction: float = 0.6) -> pd.DataFrame:
    """Fit on early host-hour observations and score the full timeline.

    This is anomaly evidence, not a verdict. The model uses only aggregate event
    counts and must be interpreted alongside deterministic detections.
    """
    numeric = ["event_count", "failed_auth", "dns_events", "remote_auth_events", "identity_changes", "distinct_domains"]
    ordered = features.sort_values("hour_bucket").reset_index(drop=True)
    if len(ordered) < 8:
        output = ordered.copy()
        output["anomaly_score"] = 0.0
        output["anomaly_flag"] = 0
        return output
    cutoff = max(4, int(len(ordered) * baseline_fraction))
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=seed)
    model.fit(ordered.loc[: cutoff - 1, numeric])
    output = ordered.copy()
    output["anomaly_score"] = -model.score_samples(ordered[numeric])
    threshold = float(output["anomaly_score"].quantile(0.95))
    output["anomaly_flag"] = (output["anomaly_score"] >= threshold).astype(int)
    return output


def attach_anomaly_evidence(alerts: pd.DataFrame, anomaly_features: pd.DataFrame) -> pd.DataFrame:
    """Attach same-host/hour anomaly evidence to alerts without altering rule hits."""
    if alerts.empty:
        output = alerts.copy()
        output["anomaly_score"] = pd.Series(dtype=float)
        return output
    lookup = anomaly_features.rename(columns={"hour_bucket": "alert_hour"})[["host", "alert_hour", "anomaly_score", "anomaly_flag"]]
    output = alerts.copy()
    output["alert_hour"] = pd.to_datetime(output["timestamp"], utc=True).dt.floor("h")
    output = output.merge(lookup, how="left", on=["host", "alert_hour"])
    output["anomaly_score"] = output["anomaly_score"].fillna(0.0)
    output["anomaly_flag"] = output["anomaly_flag"].fillna(0).astype(int)
    return output.drop(columns=["alert_hour"])
