from socintel.detections import run_detection_rules
from socintel.schema import normalize_events
from socintel.synthetic import SyntheticSOCConfig, generate_synthetic_events


def test_synthetic_scenarios_trigger_expected_rule_families():
    events = normalize_events(generate_synthetic_events(SyntheticSOCConfig(days=7, seed=42)))
    alerts = run_detection_rules(events)
    expected = {"AUTH-001", "AUTH-002", "ID-001", "DNS-001", "END-001", "NET-001"}
    assert expected.issubset(set(alerts["rule_id"]))
    assert (alerts["confidence"] > 0).all()
