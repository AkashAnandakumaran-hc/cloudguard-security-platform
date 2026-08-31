# CloudGuard — Cloud Security Posture Dashboard (spec)

Panel layout for a Splunk Simple XML dashboard fed by the searches in
`searches.md`. Build this once HEC is wired up (see `searches.md`).

```
┌─────────────────────────────────────────────────────────┐
│ Cloud Security Posture                                   │
├─────────────────────────────────────────────────────────┤
│  Posture Score        Critical Findings    Gate Pass Rate│
│      96 / 100                0                   100%    │
├─────────────────────────────────────────────────────────┤
│  Posture Score Trend (30d)                                │
│  [line chart: timechart avg(posture_score)]                │
├─────────────────────────────────────────────────────────┤
│  Findings by Severity            Findings by Category      │
│  CRITICAL  0                     IAM         ██            │
│  HIGH      0                     Network     █              │
│  MEDIUM    2                     Encryption  █              │
│  LOW       7                     Logging     (none)         │
├─────────────────────────────────────────────────────────┤
│  Recent Gate Runs (table)                                  │
│  time | actor | branch | result | posture_score            │
└─────────────────────────────────────────────────────────┘
```

## Single-value panels
- **Posture Score**: `| stats latest(posture_score)`
- **Critical Findings**: `| spath findings_by_severity.CRITICAL | stats latest(...)`
- **Gate Pass Rate**: `| stats count(eval(checks_failed=0)) as pass, count as total | eval rate=round(pass/total*100,1)`

## Notes
This is documented as a build spec rather than a live screenshot because
this environment doesn't have a running Splunk instance. When
demonstrating: sign up for the free trial, wire the HEC step into the
GitHub Action (5 lines of curl), run the pipeline twice (before/after
remediation), and this dashboard populates from real events within
minutes -- same data already sitting in `reports/`.
