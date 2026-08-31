# CloudGuard — Automated Cloud Security Control Validation & Drift Detection

A shift-left cloud security pipeline: infrastructure-as-code is scanned
against org-owned security policies, a Python risk engine turns raw
scanner output into a prioritized, business-readable posture report,
and a CI/CD gate blocks insecure changes before they can merge. A
matching incident-response runbook and Splunk integration spec close
the loop from detection to response.

Built to demonstrate platform security engineering practices: secure-by-design
review, CSPM-style scanning, policy as code, security automation, and
incident leadership — not just "ran a scanner once."

## Cost

$0. No AWS/Azure account required — all infrastructure is analyzed
statically by Checkov, never deployed. No credit card. The Splunk
integration is documented as a build spec (see `splunk/`) since it
requires a personal trial signup to go live.

## Real results (not invented numbers)

These come from actually running Checkov against the Terraform in this
repo — see `reports/before.json` and `reports/after.json` for raw output.

| | Before | After |
|---|---|---|
| Checks failed | 27 | 9 |
| Checks passed | 10 | 45 |
| Posture score | 11 / 100 | 96 / 100 |
| CRITICAL findings | 11 | 0 |
| HIGH findings | 7 | 0 |

The 9 remaining findings after remediation are intentionally left as
lower-priority backlog items (cross-region replication, customer-managed
KMS keys, etc.) — see `docs/threat-model.md` for the reasoning on what's
worth blocking a deploy over versus tracking with an owner and a date.

## Repo layout

```
infrastructure/insecure/   Deliberately misconfigured baseline (SEC-001..005 violations)
infrastructure/secure/     Remediated target state
policies/                  Org-owned controls as Rego (policy as code)
automation/risk_engine.py  Parses Checkov JSON -> severity, posture score, priority
.github/workflows/         CI/CD security gate (blocks merge on CRITICAL/HIGH)
reports/                   Real before/after scan output + generated posture reports
docs/                      Architecture, threat model, control catalog
incident-response/         Runbook for the simulated exposure scenario
splunk/                    SIEM integration spec (searches, dashboard, alerts)
```

## Run it yourself

```bash
pip install checkov
checkov -d infrastructure/insecure --compact --output json > reports/before.json
python3 automation/risk_engine.py reports/before.json --label "Before" --md reports/before_posture.md

checkov -d infrastructure/secure --compact --output json > reports/after.json
python3 automation/risk_engine.py reports/after.json --label "After" --md reports/after_posture.md
```

## Recruiter/interview walkthrough (2 minutes)

1. **Architecture** — `docs/architecture.md`: infra code -> scan -> policy
   -> risk engine -> gate -> monitoring -> response.
2. **Introduce a violation** — show `infrastructure/insecure/main.tf`:
   SSH open to `0.0.0.0/0`, wildcard IAM policy.
3. **Run the gate locally** or point to `.github/workflows/security-gate.yml`
   — explain it would fail the PR with `::error::Security gate FAILED`.
4. **Show why** — `reports/before_posture.md`: CRITICAL findings, posture
   score 11/100, ranked remediation priority.
5. **Show the fix** — `infrastructure/secure/main.tf`, diff against insecure.
6. **Re-run** — `reports/after_posture.md`: posture score 96/100, gate passes.
7. **Close the loop** — `incident-response/cloud-exposure-runbook.md`:
   what happens if this had been drift in production instead of a PR,
   and `splunk/searches.md` for how it'd surface on a live dashboard.

## What I'd build next

- Wire the Splunk HEC integration live (spec is ready, just needs a
  trial signup + one curl step in the workflow)
- Expand the control set beyond the 5 starter controls in
  `docs/security-controls.md`
- Add the AI-assisted triage layer (LLM-generated plain-English risk
  narrative per finding) as an enrichment step in `risk_engine.py`
