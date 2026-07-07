"""Entity and timeline based incident correlation for analyst review."""

from __future__ import annotations

import json
from itertools import combinations

import networkx as nx
import pandas as pd


ENTITY_COLUMNS = ("user", "host", "src_ip", "dst_ip", "dst_host", "process_name", "domain")


def correlate_alerts(alerts: pd.DataFrame, time_window_minutes: int = 90) -> tuple[pd.DataFrame, pd.DataFrame, nx.Graph]:
    """Correlate alerts through shared non-empty entities within a time window.

    The graph includes alert nodes and entity nodes. An incident is one connected
    component containing at least one alert node. Correlation is evidence for a
    human analyst, not proof that all linked events have a single cause.
    """
    graph = nx.Graph()
    output = alerts.copy()
    if output.empty:
        output["incident_id"] = pd.Series(dtype=str)
        return output, pd.DataFrame(columns=["incident_id", "alert_count", "start", "end", "max_risk_score", "entities", "rules"]), graph
    output["timestamp"] = pd.to_datetime(output["timestamp"], utc=True)
    for _, alert in output.iterrows():
        alert_node = f"alert:{alert.alert_id}"
        graph.add_node(alert_node, kind="alert", alert_id=alert.alert_id, timestamp=alert.timestamp, risk_score=float(alert.risk_score), rule_id=alert.rule_id)
        for column in ENTITY_COLUMNS:
            value = str(alert.get(column, ""))
            if value:
                entity_node = f"{column}:{value}"
                graph.add_node(entity_node, kind="entity", entity_type=column, value=value)
                graph.add_edge(alert_node, entity_node, relation=column)
    ordered = output.sort_values("timestamp")
    for (_, left), (_, right) in combinations(ordered.iterrows(), 2):
        if right.timestamp - left.timestamp > pd.Timedelta(minutes=time_window_minutes):
            continue
        shared = [column for column in ENTITY_COLUMNS if str(left.get(column, "")) and str(left.get(column, "")) == str(right.get(column, ""))]
        if shared:
            graph.add_edge(f"alert:{left.alert_id}", f"alert:{right.alert_id}", relation="temporal_shared_entity", shared_entities=",".join(shared))
    records: list[dict] = []
    assignment: dict[str, str] = {}
    index = 0
    for component in nx.connected_components(graph):
        alert_nodes = sorted(node for node in component if str(node).startswith("alert:"))
        if not alert_nodes:
            continue
        index += 1
        incident_id = f"INC-{index:03d}"
        alert_ids = [node.split(":", 1)[1] for node in alert_nodes]
        subset = output.loc[output["alert_id"].isin(alert_ids)]
        entities = sorted(node for node in component if not str(node).startswith("alert:"))
        records.append({
            "incident_id": incident_id,
            "alert_count": int(len(subset)),
            "start": subset["timestamp"].min(),
            "end": subset["timestamp"].max(),
            "max_risk_score": float(subset["risk_score"].max()),
            "entities": json.dumps(entities),
            "rules": ", ".join(sorted(subset["rule_id"].unique())),
            "contains_labeled_scenario": int(subset["is_malicious"].max()),
        })
        assignment.update({alert_id: incident_id for alert_id in alert_ids})
    output["incident_id"] = output["alert_id"].map(assignment)
    incidents = pd.DataFrame(records).sort_values("max_risk_score", ascending=False).reset_index(drop=True)
    return output, incidents, graph
