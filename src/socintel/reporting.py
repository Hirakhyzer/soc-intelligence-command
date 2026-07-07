"""Generate concise local analyst briefings from executed SOC laboratory outputs."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd


def write_analyst_brief(
    path: str | Path,
    summary: dict[str, Any],
    incidents: pd.DataFrame,
    playbooks: pd.DataFrame,
) -> None:
    """Write a local markdown briefing with explicit synthetic-data warning."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# SOC Intelligence Command — Synthetic Laboratory Brief",
        "",
        "> **Synthetic-data warning:** all telemetry, entities, labels, metrics, and incidents in this brief are fictional research artifacts. They are not operational SOC evidence.",
        "",
        "## Run summary",
        "",
        f"- Seed: `{summary['seed']}`",
        f"- Synthetic event count: `{summary['event_count']}`",
        f"- Alert count: `{summary['alert_count']}`",
        f"- Incident candidate count: `{summary['incident_count']}`",
        f"- Synthetic precision: `{summary['metrics']['synthetic_precision']:.3f}`",
        f"- Synthetic recall: `{summary['metrics']['synthetic_recall']:.3f}`",
        f"- Synthetic mean time to detect (minutes): `{summary['metrics']['synthetic_mttd_minutes']}`",
        "",
        "## Prioritized incident candidates",
        "",
        "| Incident | Alerts | Maximum risk | Rules |",
        "| --- | ---: | ---: | --- |",
    ]
    for incident in incidents.itertuples(index=False):
        lines.append(f"| {incident.incident_id} | {incident.alert_count} | {incident.max_risk_score:.2f} | {incident.rules} |")
    lines.extend(["", "## Analyst-review recommendations", ""])
    for playbook in playbooks.itertuples(index=False):
        lines.append(f"### {playbook.incident_id} — {playbook.priority}")
        lines.append("")
        lines.append(playbook.recommended_steps)
        lines.append("")
        lines.append(f"**Boundary:** {playbook.automation_boundary}")
        lines.append("")
    destination.write_text("\n".join(lines), encoding="utf-8")
