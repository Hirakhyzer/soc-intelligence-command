"""Human-review incident response recommendations.

Recommendations are intentionally non-destructive and require analyst approval.
They preserve evidence and prioritize verification before containment decisions.
"""

from __future__ import annotations

import pandas as pd


def recommend_response_steps(incidents: pd.DataFrame, alerts: pd.DataFrame) -> pd.DataFrame:
    """Generate contextual, analyst-approved response guidance per incident."""
    rows: list[dict] = []
    for incident in incidents.itertuples(index=False):
        subset = alerts.loc[alerts["incident_id"] == incident.incident_id]
        rules = set(subset["rule_id"].tolist())
        steps = [
            "Preserve relevant authentication, endpoint, DNS, and network records before any remediation.",
            "Assign an analyst owner and verify whether the observed activity is authorized.",
        ]
        if {"AUTH-001", "AUTH-002", "ID-001"}.intersection(rules):
            steps.append("Validate user sign-in context and review recent privilege changes; credential reset requires analyst approval.")
        if "NET-001" in rules:
            steps.append("Review remote-authentication targets and confirm whether the access pattern matches approved administration activity.")
        if "DNS-001" in rules:
            steps.append("Review DNS request context and resolve domain ownership/reputation through approved internal processes.")
        if "END-001" in rules:
            steps.append("Collect endpoint triage evidence; host isolation requires explicit analyst authorization and change-control approval.")
        steps.append("Document decision, evidence references, and rationale in the incident record.")
        rows.append({
            "incident_id": incident.incident_id,
            "priority": "critical" if incident.max_risk_score >= 80 else "high" if incident.max_risk_score >= 60 else "medium",
            "recommended_steps": "\n".join(f"{index + 1}. {step}" for index, step in enumerate(steps)),
            "automation_boundary": "Recommendations only. No containment, credential, or network action is executed automatically.",
        })
    return pd.DataFrame(rows)
