# SOC Intelligence Command — Research Report Template

> Populate this document only with artifacts produced by a declared local run. Do not place synthetic metrics beside real-log results without unmistakable labels.

## Task statement

[Describe the authorized telemetry source or identify the synthetic laboratory.]

## Detection and prioritization method

- Normalization boundary: [fields, data quality checks]
- Detection rules: [configured rules and thresholds]
- Anomaly evidence: [host-hour features and training window]
- Priority function: [weights and review policy]
- Correlation window: [minutes]

## Evaluation protocol

- Data origin: [synthetic / authorized local data]
- Time range: [generated]
- Ground truth basis: [synthetic labels / reviewed analyst labels / not available]
- Metrics: [precision, recall, alert volume, MTTD, or descriptive only]

## Results table

| Measure | Result | Interpretation boundary |
| --- | ---: | --- |
| Alerts | [generated] | [synthetic or authorized data] |
| Incident candidates | [generated] | Correlation candidates require analyst review |
| Precision | [generated] | Valid only where labels exist |
| Recall | [generated] | Valid only where labels exist |
| Mean time to detect | [generated] | Depends on timestamp semantics |

## Figures

- `outputs/figures/synthetic_alert_timeline.png` or [real authorized run equivalent]
- `outputs/figures/synthetic_incident_correlation_graph.png` or [real authorized run equivalent]

## Limitations and safety controls

- [False positives, missed events, baselining limits]
- [Correlation uncertainty]
- [Data authorization and privacy]
- [Human approval for impactful response]
