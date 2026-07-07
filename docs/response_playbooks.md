# Analyst response playbooks

## Operating principle

This repository produces **recommendations for analyst review**. It does not isolate devices, reset accounts, block destinations, modify identity roles, or delete evidence.

## Credential and identity activity

Applicable rules: `AUTH-001`, `AUTH-002`, `ID-001`.

1. Preserve relevant identity-provider, authentication, and role-change records.
2. Verify account ownership, work schedule, source network context, and approved administrative activity.
3. Review recent role assignments and access changes for authorization evidence.
4. Escalate credential reset, session invalidation, or privilege removal only through approved analyst and change-control processes.

## Suspicious DNS or endpoint process evidence

Applicable rules: `DNS-001`, `END-001`.

1. Preserve DNS resolution history and endpoint process-tree evidence.
2. Confirm whether the domain, binary, and process lineage are expected by approved software inventory.
3. Determine whether additional hosts/users show correlated evidence.
4. Consider host containment only after explicit analyst authorization and coordination with operational owners.

## Multi-host remote authentication

Applicable rule: `NET-001`.

1. Preserve remote-authentication and target-host logs.
2. Verify whether the source user has an approved administrative role and maintenance window.
3. Review affected targets for unexpected access or privilege changes.
4. Escalate to incident handling if corroborating evidence indicates unauthorized access.

## Closure criteria

Close an incident only after documenting: evidence reviewed, analyst decision, authorization context, remediation owner, timestamp, and residual monitoring plan.
