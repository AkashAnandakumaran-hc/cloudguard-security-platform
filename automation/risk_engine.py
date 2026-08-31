#!/usr/bin/env python3
"""
CloudGuard Risk Engine
-----------------------
Ingests raw Checkov JSON scan output and produces a normalized,
business-readable security posture report: severity classification,
a 0-100 posture score, top risks, and prioritized remediation.

This is the piece of the pipeline that turns "here is a scanner
dump" into "here is what a security engineer would tell an
engineering team to fix first, and why."

Usage:
    python3 risk_engine.py <checkov_output.json> [--label "Before"]
"""

import json
import sys
import argparse
from collections import Counter
from datetime import datetime, timezone

# Manual severity map for checks Checkov's free tier doesn't tag with
# a severity (severity tagging is a paid-tier feature in some Checkov
# versions). This is the "policy as code" judgment layer -- deciding
# what actually matters for THIS environment, not just what the tool
# reports.
SEVERITY_MAP = {
    # Public exposure / credential exposure -> CRITICAL
    "CKV_AWS_20": "CRITICAL",   # S3 ACL allows public read
    "CKV2_AWS_6": "CRITICAL",   # missing S3 public access block
    "CKV_AWS_53": "CRITICAL",
    "CKV_AWS_54": "CRITICAL",
    "CKV_AWS_55": "CRITICAL",
    "CKV_AWS_56": "CRITICAL",
    "CKV_AWS_24": "CRITICAL",   # SSH open to 0.0.0.0/0
    "CKV_AWS_62": "CRITICAL",   # wildcard admin IAM policy
    "CKV_AWS_63": "CRITICAL",   # "*" action in IAM statement
    "CKV_AWS_355": "CRITICAL",  # "*" resource in IAM statement
    "CKV2_AWS_40": "CRITICAL",  # full IAM privileges
    "CKV_AWS_286": "HIGH",
    "CKV_AWS_287": "HIGH",
    "CKV_AWS_288": "HIGH",
    "CKV_AWS_289": "HIGH",
    "CKV_AWS_290": "HIGH",
    "CKV_AWS_3": "HIGH",        # EBS not encrypted
    "CKV_AWS_189": "MEDIUM",    # EBS not using CMK
    "CKV_AWS_18": "HIGH",       # no S3 access logging
    "CKV_AWS_145": "MEDIUM",
    "CKV_AWS_382": "MEDIUM",    # unrestricted egress
    "CKV_AWS_21": "MEDIUM",     # no S3 versioning
    "CKV_AWS_144": "LOW",       # no cross-region replication
    "CKV2_AWS_61": "LOW",
    "CKV2_AWS_62": "LOW",
    "CKV_AWS_23": "LOW",
    "CKV2_AWS_5": "LOW",
    "CKV_AWS_300": "LOW",
}
DEFAULT_SEVERITY = "MEDIUM"

# Weight used for the 0-100 posture score. Deliberately front-loaded
# so a handful of criticals can't hide behind a pile of low findings.
SEVERITY_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}

FRIENDLY_NAME = {
    "CKV_AWS_20": "S3 bucket ACL allows public read access",
    "CKV2_AWS_6": "S3 bucket missing public access block",
    "CKV_AWS_24": "Security group allows SSH (22) from 0.0.0.0/0",
    "CKV_AWS_62": "IAM policy grants full admin (\"*\":\"*\") privileges",
    "CKV_AWS_63": "IAM policy statement allows \"*\" as action",
    "CKV_AWS_355": "IAM policy statement allows \"*\" as resource",
    "CKV_AWS_3": "EBS volume is not encrypted",
    "CKV_AWS_18": "S3 bucket has no access logging enabled",
    "CKV_AWS_21": "S3 bucket has no versioning enabled",
}


def classify(check_id: str) -> str:
    return SEVERITY_MAP.get(check_id, DEFAULT_SEVERITY)


def load_checkov(path: str):
    with open(path) as f:
        data = json.load(f)
    results = data.get("results", {})
    return results.get("failed_checks", []), results.get("passed_checks", []), data.get("summary", {})


def score(failed_checks, passed_checks) -> int:
    """Weighted pass-rate: a passed CRITICAL-class check earns more
    credit than a passed LOW-class check, and a failed CRITICAL-class
    check costs proportionally more. This avoids a raw penalty model
    saturating at 0 just because one bucket has four related findings."""
    all_checks = [(c["check_id"], True) for c in passed_checks] + \
                 [(c["check_id"], False) for c in failed_checks]
    if not all_checks:
        return 100
    total_weight = sum(SEVERITY_WEIGHT[classify(cid)] for cid, _ in all_checks)
    earned_weight = sum(SEVERITY_WEIGHT[classify(cid)] for cid, passed in all_checks if passed)
    return round(100 * earned_weight / total_weight) if total_weight else 100


def build_report(path: str, label: str) -> dict:
    failed, passed, summary = load_checkov(path)

    by_severity = Counter(classify(c["check_id"]) for c in failed)
    by_check = Counter(c["check_id"] for c in failed)

    top_risks = []
    for check_id, count in by_check.most_common(5):
        sev = classify(check_id)
        name = FRIENDLY_NAME.get(check_id, check_id)
        top_risks.append({"check_id": check_id, "name": name, "severity": sev, "occurrences": count})
    top_risks.sort(key=lambda r: (-SEVERITY_WEIGHT[r["severity"]], -r["occurrences"]))

    priority = []
    for r in top_risks:
        p = "P1" if r["severity"] in ("CRITICAL", "HIGH") else "P2" if r["severity"] == "MEDIUM" else "P3"
        priority.append({**r, "priority": p})

    return {
        "label": label,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "resource_count": summary.get("resource_count", 0),
        "checks_passed": summary.get("passed", 0),
        "checks_failed": summary.get("failed", 0),
        "findings_by_severity": dict(by_severity),
        "posture_score": score(failed, passed),
        "top_risks": priority,
    }


def render_markdown(report: dict) -> str:
    lines = []
    lines.append(f"# CloudGuard Posture Report — {report['label']}")
    lines.append("")
    lines.append(f"_Generated: {report['generated_at']}_")
    lines.append("")
    lines.append(f"**Resources scanned:** {report['resource_count']}  ")
    lines.append(f"**Checks passed / failed:** {report['checks_passed']} / {report['checks_failed']}  ")
    lines.append(f"**Security Posture Score:** {report['posture_score']} / 100")
    lines.append("")
    lines.append("## Findings by Severity")
    lines.append("")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lines.append(f"- **{sev}**: {report['findings_by_severity'].get(sev, 0)}")
    lines.append("")
    lines.append("## Top Risks & Remediation Priority")
    lines.append("")
    lines.append("| Priority | Severity | Finding | Check ID | Occurrences |")
    lines.append("|---|---|---|---|---|")
    for r in report["top_risks"]:
        lines.append(f"| {r['priority']} | {r['severity']} | {r['name']} | {r['check_id']} | {r['occurrences']} |")
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", help="Path to checkov JSON output")
    ap.add_argument("--label", default="Scan")
    ap.add_argument("--out", default=None, help="Optional output path for JSON report")
    ap.add_argument("--md", default=None, help="Optional output path for Markdown report")
    args = ap.parse_args()

    report = build_report(args.input, args.label)

    if args.out:
        with open(args.out, "w") as f:
            json.dump(report, f, indent=2)
    if args.md:
        with open(args.md, "w") as f:
            f.write(render_markdown(report))

    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
