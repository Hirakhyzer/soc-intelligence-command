from socintel.synthetic import SyntheticSOCConfig, generate_synthetic_events


def test_synthetic_events_are_reproducible():
    config = SyntheticSOCConfig(days=5, seed=9)
    first = generate_synthetic_events(config)
    second = generate_synthetic_events(config)
    assert first.equals(second)
    assert (first["event_id"].str.startswith("EVT-")).all()


def test_synthetic_events_include_labeled_scenarios():
    events = generate_synthetic_events(SyntheticSOCConfig(days=5, seed=7))
    expected = {"credential_pressure", "privilege_change", "lateral_auth_burst", "suspicious_dns", "suspicious_process"}
    assert expected.issubset(set(events.loc[events["is_malicious"] == 1, "scenario"]))
