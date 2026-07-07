from pathlib import Path

from socintel.anomaly import attach_anomaly_evidence, build_hourly_entity_features, fit_score_anomalies
from socintel.correlation import correlate_alerts
from socintel.detections import run_detection_rules
from socintel.ledger import append_record, verify_ledger
from socintel.schema import normalize_events
from socintel.scoring import prioritize_alerts
from socintel.synthetic import SyntheticSOCConfig, generate_synthetic_events


def test_prioritized_alerts_form_incident_candidates():
    events = normalize_events(generate_synthetic_events(SyntheticSOCConfig(days=7, seed=4)))
    anomalies = fit_score_anomalies(build_hourly_entity_features(events), seed=4)
    alerts = prioritize_alerts(attach_anomaly_evidence(run_detection_rules(events), anomalies))
    correlated, incidents, graph = correlate_alerts(alerts)
    assert len(alerts) > 0
    assert len(incidents) > 0
    assert correlated["incident_id"].notna().all()
    assert graph.number_of_nodes() >= len(alerts)
    assert alerts["risk_score"].between(0, 100).all()


def test_audit_ledger_detects_valid_record(tmp_path: Path):
    path = tmp_path / "ledger.jsonl"
    append_record(path, {"experiment": "unit_test", "seed": 1})
    assert verify_ledger(path)["valid"]
