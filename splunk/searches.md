# Splunk Integration Spec

This repo's `posture.json` output (from `automation/risk_engine.py`) is
designed to be sent to Splunk as a JSON event via HTTP Event Collector
(HEC) from the GitHub Actions workflow, so posture is tracked as a time
series, not just a point-in-time CI artifact.

## Getting this live (outside this repo, ~15 min)

1. Sign up for a Splunk free trial (60-day Enterprise trial, no credit
   card, up to 500MB/day indexing).
2. Enable HEC: Settings -> Data Inputs -> HTTP Event Collector -> New Token.
3. Add a step to `.github/workflows/security-gate.yml` that POSTs
   `posture.json` to the HEC endpoint (curl, using a GitHub Actions
   secret for the token -- never commit the token).
4. Build the searches/dashboard below against the `cloudguard` index.

## Event shape sent to Splunk

```json
{
  "event": {
    "label": "PR Scan",
    "posture_score": 96,
    "checks_passed": 45,
    "checks_failed": 9,
    "findings_by_severity": {"LOW": 7, "MEDIUM": 2},
    "top_risks": [...]
  },
  "sourcetype": "cloudguard:posture",
  "index": "cloudguard"
}
```

## Core searches (SPL)

**Posture score trend over time**
```
index=cloudguard sourcetype="cloudguard:posture"
| timechart avg(posture_score) as posture_score
```

**Any CRITICAL finding in the last 24 hours**
```
index=cloudguard sourcetype="cloudguard:posture"
| spath findings_by_severity.CRITICAL
| where 'findings_by_severity.CRITICAL' > 0
```

**Gate failures by repository / branch**
```
index=cloudguard sourcetype="cloudguard:posture" checks_failed>0
| stats count by branch, actor
| sort -count
```

**Repeated failures from the same author (near-miss pattern, ties to the runbook)**
```
index=cloudguard sourcetype="cloudguard:posture" checks_failed>0
| stats count as failed_gates by actor
| where failed_gates >= 3
```

## Alerts (proposed)

| Alert | Trigger | Action |
|---|---|---|
| Critical exposure attempt | Any event with `findings_by_severity.CRITICAL > 0` | Notify #platform-security Slack, page on-call if `branch=main` |
| Posture regression | `avg(posture_score)` drops >10 points week-over-week | Weekly digest to eng leads |
| Repeat offender pattern | Same author, 3+ failed gates in 7 days | Flag for security team follow-up (see runbook) |
