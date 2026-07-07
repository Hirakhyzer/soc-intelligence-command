"""Run the complete synthetic defensive SOC intelligence laboratory.

This command produces only fictional telemetry and clearly labeled synthetic
metrics. It does not connect to systems, execute response actions, or ingest real
security logs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from socintel.anomaly import attach_anomaly_evidence, build_hourly_entity_features, fit_score_anomalies
from socintel.config import ensure_output_dirs, set_seed
from socintel.correlation import correlate_alerts
from socintel.detections import run_detection_rules
from socintel.ledger import append_record, verify_ledger
from socintel.metrics import synthetic_alert_metrics
from socintel.playbooks import recommend_response_steps
from socintel.reporting import write_analyst_brief
from socintel.schema import normalize_events
from socintel.scoring import prioritize_alerts
from socintel.synthetic import SyntheticSOCConfig, generate_synthetic_events
from socintel.taxonomy import add_tactic_tags
from socintel.visualization import plot_alert_timeline, plot_alert_volume, plot_incident_graph, plot_priority_distribution


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a safe synthetic SOC intelligence laboratory.")
    parser.add_argument("--days", type=int, default=14)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", default="outputs")
    args = parser.parse_args()

    set_seed(args.seed)
    events = normalize_events(generate_synthetic_events(SyntheticSOCConfig(days=args.days, seed=args.seed)))
    anomalies = fit_score_anomalies(build_hourly_entity_features(events), seed=args.seed)
    detected = add_tactic_tags(run_detection_rules(events))
    enriched = attach_anomaly_evidence(detected, anomalies)
    prioritized = prioritize_alerts(enriched)
    alert_incidents, incidents, graph = correlate_alerts(prioritized)
    playbooks = recommend_response_steps(incidents, alert_incidents)
    metrics = synthetic_alert_metrics(events, alert_incidents)

    outputs = ensure_output_dirs(args.output_dir)
    events.to_csv(outputs["results"] / "synthetic_events.csv", index=False)
    anomalies.to_csv(outputs["results"] / "synthetic_host_hour_anomalies.csv", index=False)
    alert_incidents.to_csv(outputs["results"] / "synthetic_alerts.csv", index=False)
    incidents.to_csv(outputs["results"] / "synthetic_incidents.csv", index=False)
    playbooks.to_csv(outputs["results"] / "synthetic_response_recommendations.csv", index=False)
    plot_alert_volume(alert_incidents, outputs["figures"] / "synthetic_alert_volume_by_rule.png")
    plot_alert_timeline(alert_incidents, outputs["figures"] / "synthetic_alert_timeline.png")
    plot_priority_distribution(alert_incidents, outputs["figures"] / "synthetic_priority_distribution.png")
    plot_incident_graph(graph, outputs["figures"] / "synthetic_incident_correlation_graph.png")

    ledger_path = outputs["results"] / "audit_ledger.jsonl"
    append_record(ledger_path, {
        "experiment": "synthetic_soc_lab",
        "seed": args.seed,
        "days": args.days,
        "event_count": len(events),
        "alert_count": len(alert_incidents),
        "incident_count": len(incidents),
        "metrics": metrics,
        "boundary": "Synthetic defensive research telemetry only; no automated response action.",
    })
    summary = {
        "data_origin": "synthetic fictional SOC telemetry",
        "seed": args.seed,
        "days": args.days,
        "metrics": metrics,
        "event_count": int(len(events)),
        "alert_count": int(len(alert_incidents)),
        "incident_count": int(len(incidents)),
        "ledger": verify_ledger(ledger_path),
        "response_boundary": "Recommendations require human analyst authorization; no automatic containment or account action is performed.",
        "taxonomy_boundary": "Tactic labels are educational MITRE-style annotations, not official coverage claims.",
    }
    (outputs["results"] / "synthetic_soc_summary.json").write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")
    write_analyst_brief(outputs["reports"] / "synthetic_soc_brief.md", summary, incidents, playbooks)
    print(json.dumps(summary, indent=2, default=str))


if __name__ == "__main__":
    main()
