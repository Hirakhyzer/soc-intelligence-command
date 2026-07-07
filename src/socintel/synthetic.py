"""Deterministic synthetic SOC telemetry for safe defensive experimentation.

All hosts, accounts, IP addresses, domains, events, and labels are fictional.
The generator models high-level defender-relevant patterns without delivering
exploit instructions or malicious tooling.
"""

from __future__ import annotations

from dataclasses import dataclass
import uuid

import numpy as np
import pandas as pd


@dataclass(frozen=True)
class SyntheticSOCConfig:
    """Controls reproducible synthetic security telemetry generation."""

    days: int = 14
    seed: int = 42
    include_scenarios: bool = True

    def __post_init__(self) -> None:
        if self.days < 3:
            raise ValueError("Use at least three days for useful time-based detection.")


def generate_synthetic_events(config: SyntheticSOCConfig | None = None) -> pd.DataFrame:
    """Generate multi-source benign events plus labeled defensive detection scenarios."""
    cfg = config or SyntheticSOCConfig()
    rng = np.random.default_rng(cfg.seed)
    start = pd.Timestamp("2025-04-01 00:00:00", tz="UTC")
    users = ["alex.chen", "maria.khan", "sam.lee", "ops.service"]
    hosts = ["workstation-01", "workstation-02", "workstation-03", "fileserver-01", "finance-app-01"]
    criticality = {"workstation-01": "medium", "workstation-02": "medium", "workstation-03": "medium", "fileserver-01": "high", "finance-app-01": "critical"}
    domains = ["intranet.example", "updates.example", "collaboration.example", "identity.example"]
    rows: list[dict] = []

    def add(timestamp, source_type, event_type, action, status, user="", host="", src_ip="", dst_ip="", dst_host="", process_name="", parent_process="", domain="", malicious=0, scenario="benign"):
        rows.append({
            "event_id": uuid.uuid4().hex[:18], "timestamp": timestamp, "source_type": source_type,
            "event_type": event_type, "action": action, "status": status, "user": user, "host": host,
            "src_ip": src_ip, "dst_ip": dst_ip, "dst_host": dst_host, "process_name": process_name,
            "parent_process": parent_process, "domain": domain,
            "asset_criticality": criticality.get(host or dst_host, "medium"),
            "is_malicious": malicious, "scenario": scenario,
        })

    for offset in range(cfg.days * 24):
        timestamp = start + pd.Timedelta(hours=offset)
        business = timestamp.dayofweek < 5 and 7 <= timestamp.hour <= 19
        event_count = 7 if business else 3
        for _ in range(event_count):
            user = str(rng.choice(users))
            host = str(rng.choice(hosts[:3]))
            ip = f"10.0.0.{int(rng.integers(10, 90))}"
            add(timestamp + pd.Timedelta(minutes=int(rng.integers(0, 55))), "identity", "authentication", "login", "success", user=user, host=host, src_ip=ip)
            add(timestamp + pd.Timedelta(minutes=int(rng.integers(0, 55))), "endpoint", "process", "start", "success", user=user, host=host, process_name=str(rng.choice(["browser.exe", "office_suite.exe", "collaboration_client.exe"])), parent_process="shell.exe")
            add(timestamp + pd.Timedelta(minutes=int(rng.integers(0, 55))), "dns", "dns_query", "resolve", "success", host=host, src_ip=ip, domain=str(rng.choice(domains)))
        if business:
            add(timestamp + pd.Timedelta(minutes=30), "network", "network_connection", "connect", "allowed", user="ops.service", host="fileserver-01", src_ip="10.0.0.15", dst_ip="10.0.0.30", dst_host="finance-app-01")

    if cfg.include_scenarios:
        base = start + pd.Timedelta(days=max(2, cfg.days - 5), hours=2)
        suspicious_ip = "198.51.100.23"
        user = "alex.chen"
        host = "workstation-03"
        for attempt in range(10):
            add(base + pd.Timedelta(minutes=attempt * 2), "identity", "authentication", "login", "failure", user=user, host=host, src_ip=suspicious_ip, malicious=1, scenario="credential_pressure")
        add(base + pd.Timedelta(minutes=22), "identity", "authentication", "login", "success", user=user, host=host, src_ip=suspicious_ip, malicious=1, scenario="credential_pressure")
        add(base + pd.Timedelta(minutes=31), "identity", "identity_change", "role_assignment", "success", user=user, host="finance-app-01", src_ip=suspicious_ip, malicious=1, scenario="privilege_change")
        for index, target in enumerate(["fileserver-01", "finance-app-01", "workstation-01", "workstation-02"]):
            add(base + pd.Timedelta(minutes=40 + index * 3), "network", "remote_auth", "authenticate", "success", user=user, host=host, src_ip=suspicious_ip, dst_host=target, dst_ip=f"10.0.0.{30 + index}", malicious=1, scenario="lateral_auth_burst")
        for index in range(5):
            add(base + pd.Timedelta(minutes=56 + index), "dns", "dns_query", "resolve", "success", host=host, src_ip=suspicious_ip, domain=f"telemetry-{index}-a9f3c7d2e6b1f0.example.invalid", malicious=1, scenario="suspicious_dns")
        add(base + pd.Timedelta(minutes=67), "endpoint", "process", "start", "success", user=user, host=host, src_ip=suspicious_ip, process_name="unknown_binary.exe", parent_process="email_client.exe", malicious=1, scenario="suspicious_process")

    return pd.DataFrame(rows).sort_values("timestamp").reset_index(drop=True)
