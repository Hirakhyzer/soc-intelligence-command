"""Defensive SOC research visualizations generated from executed local runs."""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
import networkx as nx
import pandas as pd


def _path(path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    return destination


def plot_alert_volume(alerts: pd.DataFrame, path: str | Path) -> None:
    """Plot alert counts by rule from an executed experiment."""
    counts = alerts["rule_id"].value_counts().sort_values(ascending=True)
    figure, axis = plt.subplots(figsize=(8, 4.8))
    axis.barh(counts.index, counts.values)
    axis.set(xlabel="Alert count", ylabel="Detection rule", title="SOC alert volume by rule")
    axis.grid(True, axis="x", alpha=0.25)
    figure.tight_layout(); figure.savefig(_path(path), dpi=250); plt.close(figure)


def plot_alert_timeline(alerts: pd.DataFrame, path: str | Path) -> None:
    """Plot risk-scored alerts across time."""
    figure, axis = plt.subplots(figsize=(10.5, 4.8))
    for rule, group in alerts.groupby("rule_id"):
        axis.scatter(group["timestamp"], group["risk_score"], label=rule, s=42)
    axis.set(xlabel="Time", ylabel="Risk score", title="Prioritized alert timeline", ylim=(0, 100))
    axis.grid(True, alpha=0.25)
    axis.legend(ncol=3, fontsize=8)
    figure.tight_layout(); figure.savefig(_path(path), dpi=250); plt.close(figure)


def plot_incident_graph(graph: nx.Graph, path: str | Path) -> None:
    """Render a bounded entity-alert correlation graph for analyst review."""
    figure, axis = plt.subplots(figsize=(10, 7.5))
    if graph.number_of_nodes() == 0:
        axis.text(0.5, 0.5, "No incidents generated", ha="center", va="center")
        axis.axis("off")
    else:
        layout = nx.spring_layout(graph, seed=42, k=0.8)
        alert_nodes = [node for node, data in graph.nodes(data=True) if data.get("kind") == "alert"]
        entity_nodes = [node for node, data in graph.nodes(data=True) if data.get("kind") == "entity"]
        nx.draw_networkx_edges(graph, layout, ax=axis, alpha=0.35)
        nx.draw_networkx_nodes(graph, layout, nodelist=entity_nodes, node_size=220, ax=axis, label="Entities")
        nx.draw_networkx_nodes(graph, layout, nodelist=alert_nodes, node_size=370, node_shape="s", ax=axis, label="Alerts")
        labels = {node: str(node).replace("alert:", "A:")[:24] for node in graph.nodes}
        nx.draw_networkx_labels(graph, layout, labels=labels, font_size=6, ax=axis)
        axis.set_title("Entity and timeline incident correlation graph")
        axis.legend(loc="upper right")
        axis.axis("off")
    figure.tight_layout(); figure.savefig(_path(path), dpi=250); plt.close(figure)


def plot_priority_distribution(alerts: pd.DataFrame, path: str | Path) -> None:
    """Plot analyst queue priorities."""
    order = ["low", "medium", "high", "critical"]
    counts = alerts["priority"].value_counts().reindex(order, fill_value=0)
    figure, axis = plt.subplots(figsize=(7.2, 4.8))
    axis.bar(counts.index, counts.values)
    axis.set(xlabel="Priority", ylabel="Alert count", title="Analyst queue priority distribution")
    axis.grid(True, axis="y", alpha=0.25)
    figure.tight_layout(); figure.savefig(_path(path), dpi=250); plt.close(figure)
