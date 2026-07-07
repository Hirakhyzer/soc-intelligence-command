# Methodology

## Scope and safety boundary

SOC Intelligence Command is a defensive research prototype. It ingests **synthetic fictional telemetry** by default and makes no network connections, does not run commands on endpoints, and does not perform automatic containment. Real telemetry, if added later, must be authorized, minimized, de-identified where appropriate, and retained outside version control.

## 1. Canonical event model

Multi-source records are normalized to a common event schema containing timestamp, source type, event type, action/status, user, host, source/destination network context, process/domain context, asset criticality, and optional synthetic labels. Normalization fails when timestamps are not parseable and does not invent missing evidence.

## 2. Transparent detection rules

The synthetic laboratory implements high-level rules for:

| Rule | Evidence pattern | Intended interpretation |
| --- | --- | --- |
| `AUTH-001` | Repeated authentication failures for a user/source inside a time window | Possible credential-pressure or configuration issue; verify context |
| `AUTH-002` | Successful authentication outside the configured synthetic baseline | Requires account and schedule review |
| `ID-001` | Successful role assignment | Privilege change requiring authorization review |
| `DNS-001` | Long, character-diverse DNS name | Heuristic DNS anomaly; not proof of harmful activity |
| `END-001` | Unrecognized process lineage from an email client | Endpoint context requiring triage evidence |
| `NET-001` | Multiple remote authentications across hosts in a short interval | Potential lateral-access pattern or approved administration |

Rules are intentionally interpretable. Thresholds are configuration choices that must be calibrated on real organizational baselines before operational use.

## 3. Anomaly evidence

The project aggregates host-hour features: event count, failed authentications, DNS volume, remote-authentication count, identity-change count, and distinct domain count. Isolation Forest is trained on the early portion of the synthetic timeline, then scores the full timeline.

The anomaly score only supplements rule evidence. It is not an incident verdict and should not be interpreted without checking contributing events.

## 4. Alert prioritization

Priority score is an explicit weighted function of severity, detection confidence, asset criticality, normalized anomaly evidence, and recency. This score ranks an analyst queue. It does not authorize any automated response.

## 5. Incident correlation

Alerts are connected through shared entities—user, host, source/destination IP, destination host, process, and domain—when they occur within a configurable temporal window. Connected graph components become incident candidates. Correlation can over-link activity in dense environments, so it is evidence for review, not proof of a common root cause.

## 6. Analyst response recommendations

Response playbooks recommend evidence preservation, validation of authorization, contextual review, and escalation. Account resets, endpoint isolation, blocking, deletion, or other impactful changes always require explicit human approval and organizational procedures.

## 7. Synthetic evaluation

The synthetic generator labels fictional scenarios. Metrics include event-linked precision, recall, alert-volume reduction, and mean time to detect. These values are valid only for regression testing and comparison inside the synthetic laboratory. They must never be presented as operational SOC performance.

## 8. Auditability

Each synthetic run appends a hash-chained JSONL ledger record containing seed, duration, counts, metrics, and the safety boundary. The ledger can be verified locally to detect altered history.

## Limitations

- Synthetic telemetry cannot represent an organization's event distribution, adversary behavior, asset inventory, or alert triage process.
- Fixed heuristics can produce false positives and false negatives.
- Entity correlation can over-connect or under-connect events.
- Anomaly models can drift and require reviewed baselines.
- The project does not supply detection content for destructive actions, exploit development, credential misuse, or automated containment.
