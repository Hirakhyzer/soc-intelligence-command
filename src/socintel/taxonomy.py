"""Educational MITRE-style tactic labeling for analyst context.

These labels are lightweight research annotations, not official ATT&CK coverage
claims, and should be reviewed against an organization's detection taxonomy.
"""

from __future__ import annotations

import pandas as pd


RULE_TO_TACTICS = {
    "AUTH-001": "Credential Access; Initial Access",
    "AUTH-002": "Initial Access",
    "ID-001": "Privilege Escalation; Persistence",
    "DNS-001": "Command and Control",
    "END-001": "Execution",
    "NET-001": "Lateral Movement",
}


def add_tactic_tags(alerts: pd.DataFrame) -> pd.DataFrame:
    """Attach transparent educational tactic labels to alert rows."""
    output = alerts.copy()
    output["tactic_tags"] = output["rule_id"].map(RULE_TO_TACTICS).fillna("Unmapped")
    return output
