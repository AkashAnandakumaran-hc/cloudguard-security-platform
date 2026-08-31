# Platform Security Incident Runbook: Attempted Cloud Exposure via IaC Change

## Scenario

A pull request modifies `infrastructure/` to (a) open SSH (port 22) to
`0.0.0.0/0` on a security group and (b) attach an IAM policy with
`Action: "*"`, `Resource: "*"` to a role. This simulates a real class of
incident: a well-intentioned but insecure infra change, or a compromised
contributor account pushing a change to weaken controls before a
follow-on attack.

## Response phases

### 1. Detection
- CloudGuard's GitHub Actions security gate runs Checkov + the risk
  engine on every PR touching `infrastructure/`.
- The gate finds CKV_AWS_24 (open SSH) and CKV_AWS_62/63/355 (wildcard
  IAM) as CRITICAL findings.
- `posture_score` drops sharply; CI job fails with `::error::` annotation.

### 2. Validation
- Security engineer reviews the posture report artifact (`posture.md`)
  attached to the failed CI run.
- Confirms the findings are genuine (not a scanner false positive) by
  reading the diff directly: is `0.0.0.0/0` actually present, is the
  IAM `Action` actually `"*"`.
- Checks who authored the PR and whether the change was expected
  (scheduled maintenance vs. unexpected).

### 3. Risk assessment
- Because this was caught at the PR stage, **no production exposure
  occurred** -- this is a near-miss, not a live incident. Severity is
  scoped as "control validation success," not "breach."
- If the same pattern were found in an *already-applied* resource
  (drift, not a proposed change), this escalates to a live incident:
  assume the SSH port may have already been probed/scanned by internet-wide
  scanners (Shodan-class exposure can occur within minutes of exposure).

### 4. Containment decision
- PR stage: containment is trivial -- do not approve/merge. Gate already
  blocked it automatically.
- Drift stage (hypothetical): would require immediately reapplying the
  last-known-good Terraform state to close the exposed port, rotating
  any credentials associated with the overly-permissive IAM role, and
  reviewing CloudTrail/VPC Flow Logs for the exposure window.

### 5. Remediation
- Author updates the PR: restrict ingress CIDR, scope the IAM policy to
  specific actions/resources (see `infrastructure/secure/main.tf` for
  the target state).
- Re-run the gate; confirm posture score returns to baseline (96/100 in
  this repo's reference scan) and CRITICAL/HIGH count is 0.

### 6. Verification
- `reports/after_posture.md` is the artifact of record showing the
  environment returned to an acceptable posture.
- PR merges only after a green gate run.

### 7. Lessons learned / follow-up
- Root cause: no local pre-commit hook caught this before it reached
  CI; recommend adding `checkov` as a pre-commit hook so contributors
  get instant feedback instead of waiting on a CI failure.
- Track the 9 residual LOW/MEDIUM findings (cross-region replication,
  CMK usage) as backlog items with owners, per `docs/security-controls.md`.
- Feed this event into Splunk (`splunk/searches.md`) so repeated
  attempts by the same author/branch trigger an alert -- one bad PR is
  a mistake, three in a week from the same source is a signal.

## Communication

| Audience | What they're told |
|---|---|
| PR author | Direct, specific: which control failed, which file/line, how to fix (linked to `infrastructure/secure/main.tf` as reference) |
| Engineering manager | Summary only if pattern repeats or if drift (not PR-stage) is involved |
| Security leadership | Included in weekly posture trend review, not a one-off unless it was a live exposure |
