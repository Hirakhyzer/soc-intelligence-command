# Security telemetry data boundary

This repository runs immediately using fictional synthetic telemetry. Real security logs are **not required** and should never be uploaded to GitHub without explicit authorization.

## Synthetic laboratory

Run:

```bash
python scripts/run_synthetic_soc_lab.py
```

The command generates local synthetic event tables under `outputs/results/`. These are fictional and safe for demonstration.

## Optional future authorized telemetry

If you later add a local adapter, place authorized, de-identified exports in:

```text
data/raw/
```

Potential sources may include identity/authentication, endpoint, DNS, network, and asset-inventory events. The project requires written authorization and a schema adapter before attempting to process any real operational log.

## Minimum normalized fields

| Field | Purpose |
| --- | --- |
| timestamp | Event ordering and time-window correlation |
| source_type / event_type | Telemetry origin and semantic category |
| user / host | Identity and endpoint correlation |
| source/destination network context | Network entity correlation |
| process_name / parent_process | Endpoint context where available |
| domain | DNS context where available |
| status and action | Rule interpretation |
| asset_criticality | Transparent triage prioritization |

Do not infer missing evidence. Empty fields must stay empty and lower-confidence decisions should be documented.
