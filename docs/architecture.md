# CloudGuard Architecture

## Purpose

CloudGuard is a control-validation and drift-detection pipeline. It does
not just report on misconfigurations after the fact -- it prevents them
from reaching a deployable state, measures posture over time, and feeds
findings into a detection/response workflow.

## Pipeline

```
Infrastructure Code (Terraform)
        |
        v
IaC Security Scan (Checkov)  <-- enforces org policy (policies/*.rego, conceptually)
        |
        v
Risk Engine (Python)  --> severity classification, weighted posture score
        |
        v
   +----+----+
   |         |
   v         v
CI/CD Gate   Security Event Feed
(GitHub      (JSON -> Splunk HEC,
 Actions)     see splunk/)
   |         |
   v         v
PASS/BLOCK   Dashboard + Alerting
   |
   v
Remediation --> re-scan --> posture improvement (measured, not assumed)
```

## Components

| Layer | Tool | Role |
|---|---|---|
| Infrastructure definition | Terraform | Declares cloud resources (analyzed statically, never applied) |
| Static analysis | Checkov | Enforces CIS-aligned benchmark checks against Terraform |
| Policy layer | OPA / Rego (`policies/`) | Org-owned control definitions, independent of any single scanner |
| Automation | Python (`automation/risk_engine.py`) | Normalizes findings, assigns severity, computes posture score, ranks remediation priority |
| Shift-left gate | GitHub Actions (`.github/workflows/security-gate.yml`) | Blocks merge on CRITICAL/HIGH findings |
| Monitoring | Splunk (`splunk/`) | Ingests posture events, dashboards trend over time, alerts on regressions |
| Response | `incident-response/` | Runbook for when the gate catches a live exposure attempt |

## Design principles

1. **Fail closed on high-severity findings, fail open on low-severity ones.**
   A missing cross-region replication config shouldn't block a deploy;
   a public S3 bucket should.
2. **Policy is versioned code, not a wiki page.** `policies/*.rego` and
   the severity map in `risk_engine.py` are the actual source of truth
   for what "insecure" means in this environment, and they're reviewed
   like any other code change.
3. **Every claim is a real, reproducible scan result.** The before/after
   numbers in `reports/` come from actually running Checkov against the
   Terraform in this repo -- nothing here is a mocked number.
