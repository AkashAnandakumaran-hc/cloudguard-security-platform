# CloudGuard Security Controls

Org-level policy IDs referenced throughout this repo (`policies/`,
`docs/threat-model.md`, incident runbook).

| ID | Control | Enforced By |
|---|---|---|
| SEC-001 | Public storage prohibited by default | `policies/network.rego` (conceptually), Checkov CKV_AWS_53/54/55/56, CKV2_AWS_6 |
| SEC-002 | Administrative ports (22, 3389) must not be internet-exposed | `policies/network.rego`, CKV_AWS_24 |
| SEC-003 | All storage encrypted at rest by default | `policies/encryption.rego`, CKV_AWS_3, CKV_AWS_145 |
| SEC-004 | Access logging enabled on all data stores | CKV_AWS_18 |
| SEC-005 | No wildcard IAM actions or resources | `policies/iam.rego`, CKV_AWS_62/63/355, CKV2_AWS_40 |

## Severity → priority mapping

Used by `automation/risk_engine.py` to rank remediation.

| Severity | Priority | SLA (proposed) |
|---|---|---|
| CRITICAL | P1 | Block merge; remediate before any deploy |
| HIGH | P1 | Block merge; remediate before any deploy |
| MEDIUM | P2 | Remediate within current sprint |
| LOW | P3 | Backlog, owner assigned, tracked to closure |

## Note on scope

These five controls are a deliberately small, high-signal starter set --
a real platform security program has dozens of controls across identity,
network, data, and logging. The point of this repo is to demonstrate the
*pattern* (policy as code -> automated enforcement -> measured posture),
which scales to a larger control set without changing the architecture.
