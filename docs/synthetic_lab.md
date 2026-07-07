# Synthetic SOC laboratory

## Purpose

The laboratory makes the full SOC pipeline runnable without external logs. It generates a fictional multi-source event stream, injects labeled high-level scenarios, runs detections and anomaly scoring, prioritizes alerts, correlates incidents, creates response recommendations, writes a hash-chained ledger, and generates figures.

## Command

```bash
python scripts/run_synthetic_soc_lab.py
```

Optional controls:

```bash
python scripts/run_synthetic_soc_lab.py --days 21 --seed 42
```

## Fictional scenarios

| Scenario | Synthetic defender-relevant pattern | Main rule family |
| --- | --- | --- |
| `credential_pressure` | Repeated failed authentication followed by an unusual successful login | `AUTH-001`, `AUTH-002` |
| `privilege_change` | Role assignment after suspicious identity context | `ID-001` |
| `lateral_auth_burst` | Multiple remote-authentication targets in a short period | `NET-001` |
| `suspicious_dns` | Long, high-diversity query names | `DNS-001` |
| `suspicious_process` | Unrecognized process from email-client lineage | `END-001` |

The scenarios are not attack recipes, malware simulations, or real incidents. They are controlled patterns used for defensive detection research.

## Outputs

```text
outputs/results/synthetic_events.csv
outputs/results/synthetic_host_hour_anomalies.csv
outputs/results/synthetic_alerts.csv
outputs/results/synthetic_incidents.csv
outputs/results/synthetic_response_recommendations.csv
outputs/results/synthetic_soc_summary.json
outputs/results/audit_ledger.jsonl
outputs/reports/synthetic_soc_brief.md

outputs/figures/synthetic_alert_volume_by_rule.png
outputs/figures/synthetic_alert_timeline.png
outputs/figures/synthetic_priority_distribution.png
outputs/figures/synthetic_incident_correlation_graph.png
```

## Interpretation rules

- Keep the word **synthetic** in all filenames and figure captions.
- Synthetic precision, recall, alert-volume reduction, and MTTD are regression-test metrics only.
- Do not claim an organization’s detection performance, adversary prevalence, or operational maturity from this demo.
- Incident recommendations must remain human-reviewed; the code performs no containment action.
