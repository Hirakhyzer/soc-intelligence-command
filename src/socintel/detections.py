"""Transparent defensive detection rules over normalized events."""

from __future__ import annotations

from collections import defaultdict
import math

import pandas as pd


ALERT_COLUMNS = (
    "alert_id", "timestamp", "rule_id", "title", "severity", "confidence", "event_id",
    "user", "host", "src_ip", "dst_ip", "dst_host", "process_name", "domain",
    "asset_criticality", "scenario", "is_malicious", "evidence",
)


def run_detection_rules(events: pd.DataFrame, failure_threshold: int = 6, window_minutes: int = 30) -> pd.DataFrame:
    """Run deterministic detection rules and return one record per rule hit."""
    alerts: list[dict] = []
    alerts.extend(_failed_login_bursts(events, failure_threshold, window_minutes))
    alerts.extend(_unusual_successful_logins(events))
    alerts.extend(_privilege_changes(events))
    alerts.extend(_suspicious_dns(events))
    alerts.extend(_suspicious_process_lineage(events))
    alerts.extend(_lateral_authentication_bursts(events, min_targets=3, window_minutes=45))
    if not alerts:
        return pd.DataFrame(columns=ALERT_COLUMNS)
    output = pd.DataFrame(alerts)
    return output.loc[:, ALERT_COLUMNS].sort_values("timestamp").reset_index(drop=True)


def _alert(event: pd.Series, rule_id: str, title: str, severity: str, confidence: float, evidence: str) -> dict:
    return {
        "alert_id": f"{rule_id}-{event.event_id}", "timestamp": event.timestamp, "rule_id": rule_id,
        "title": title, "severity": severity, "confidence": float(confidence), "event_id": event.event_id,
        "user": event.user, "host": event.host, "src_ip": event.src_ip, "dst_ip": event.dst_ip,
        "dst_host": event.dst_host, "process_name": event.process_name, "domain": event.domain,
        "asset_criticality": event.asset_criticality, "scenario": event.scenario,
        "is_malicious": int(event.is_malicious), "evidence": evidence,
    }


def _failed_login_bursts(events: pd.DataFrame, threshold: int, window_minutes: int) -> list[dict]:
    failures = events.loc[(events["event_type"] == "authentication") & (events["status"] == "failure")].sort_values("timestamp")
    alerts: list[dict] = []
    for _, group in failures.groupby(["user", "src_ip"], dropna=False):
        times = group["timestamp"].tolist()
        for position, (_, event) in enumerate(group.iterrows()):
            lower = event.timestamp - pd.Timedelta(minutes=window_minutes)
            count = sum(lower <= value <= event.timestamp for value in times[: position + 1])
            if count == threshold:
                alerts.append(_alert(event, "AUTH-001", "Repeated authentication failures", "high", 0.88, f"{count} failed logins for the same user/source in {window_minutes} minutes"))
    return alerts


def _unusual_successful_logins(events: pd.DataFrame) -> list[dict]:
    candidates = events.loc[(events["event_type"] == "authentication") & (events["status"] == "success")]
    return [
        _alert(event, "AUTH-002", "Unusual successful authentication time", "medium", 0.64, "Successful authentication occurred outside the synthetic business-hour baseline")
        for _, event in candidates.iterrows() if event.timestamp.hour < 5
    ]


def _privilege_changes(events: pd.DataFrame) -> list[dict]:
    candidates = events.loc[(events["event_type"] == "identity_change") & (events["action"] == "role_assignment") & (events["status"] == "success")]
    return [_alert(event, "ID-001", "Privilege assignment observed", "high", 0.92, "Successful role assignment requires analyst validation") for _, event in candidates.iterrows()]


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    probabilities = [value.count(symbol) / len(value) for symbol in set(value)]
    return -sum(probability * math.log2(probability) for probability in probabilities)


def _suspicious_dns(events: pd.DataFrame) -> list[dict]:
    candidates = events.loc[events["event_type"] == "dns_query"]
    alerts: list[dict] = []
    for _, event in candidates.iterrows():
        domain = str(event.domain)
        if len(domain) >= 38 and _entropy(domain) >= 3.5:
            alerts.append(_alert(event, "DNS-001", "Unusually long high-entropy DNS name", "medium", 0.72, "Domain length and character diversity exceed the configured research heuristic"))
    return alerts


def _suspicious_process_lineage(events: pd.DataFrame) -> list[dict]:
    candidates = events.loc[events["event_type"] == "process"]
    return [
        _alert(event, "END-001", "Unrecognized process launched from email client", "high", 0.84, "Configured synthetic process-lineage heuristic matched")
        for _, event in candidates.iterrows()
        if event.process_name == "unknown_binary.exe" and event.parent_process == "email_client.exe"
    ]


def _lateral_authentication_bursts(events: pd.DataFrame, min_targets: int, window_minutes: int) -> list[dict]:
    candidates = events.loc[(events["event_type"] == "remote_auth") & (events["status"] == "success")].sort_values("timestamp")
    alerts: list[dict] = []
    for _, group in candidates.groupby(["user", "src_ip"], dropna=False):
        for _, event in group.iterrows():
            lower = event.timestamp - pd.Timedelta(minutes=window_minutes)
            window = group.loc[(group["timestamp"] >= lower) & (group["timestamp"] <= event.timestamp)]
            targets = window["dst_host"].replace("", pd.NA).dropna().nunique()
            if targets == min_targets:
                alerts.append(_alert(event, "NET-001", "Multiple remote authentications across hosts", "high", 0.86, f"Successful remote authentication reached {targets} distinct hosts in {window_minutes} minutes"))
    return alerts
