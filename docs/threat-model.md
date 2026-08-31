# CloudGuard Threat Model

Scope: the cloud platform environment represented by `infrastructure/`
(object storage, compute security groups, IAM, block storage).

## Method

Lightweight STRIDE pass against each resource class, mapped to the
control that mitigates it and the check that verifies the control held.

| Asset | Threat (STRIDE) | Scenario | Mitigating Control | Verified By |
|---|---|---|---|---|
| S3 data bucket | Information Disclosure | Bucket ACL/policy misconfigured to public-read; data exfiltrated by anyone with the bucket name | SEC-001: block all public access, private ACL | CKV_AWS_53/54/55/56, CKV2_AWS_6 |
| S3 data bucket | Tampering | Object overwritten/deleted without trace | Versioning + lifecycle policy | CKV_AWS_21, CKV2_AWS_61 |
| S3 data bucket | Repudiation | No record of who accessed/modified objects | Access logging to dedicated log bucket | CKV_AWS_18 |
| S3 data bucket | Information Disclosure (at rest) | Storage volume compromised at the disk layer | Default encryption (KMS) | CKV_AWS_145, CKV_AWS_3 |
| Security group | Elevation of Privilege | SSH exposed to 0.0.0.0/0, brute-forced or credential-stuffed | Restrict ingress to known CIDR, remove admin ports from internet | CKV_AWS_24 |
| Security group | Information Disclosure | Unrestricted egress enables data exfiltration from a compromised host | Restrict egress to VPC CIDR | CKV_AWS_382 |
| IAM policy | Elevation of Privilege | Wildcard `Action: "*"` / `Resource: "*"` lets a compromised identity pivot to full account takeover | Least-privilege, resource-scoped policy | CKV_AWS_62/63/355, CKV2_AWS_40 |
| EBS volume | Information Disclosure | Volume snapshot shared or attached elsewhere, disk read in cleartext | Encryption at rest | CKV_AWS_3, CKV_AWS_189 |

## Residual risk (post-remediation)

The `after` scan still shows 9 lower-severity findings (see
`reports/after_posture.md`): missing cross-region replication, EBS
encrypted with the AWS-managed key rather than a customer-managed KMS
key, and a couple of lifecycle/notification checks. These are
intentionally left as **P2/P3** items -- a senior call is knowing which
findings justify blocking a deploy and which belong on a backlog with
an owner and a date, not fixing everything with equal urgency.

## Out of scope for this exercise

- Network topology beyond the security group layer (VPC peering, transit
  gateways, NACLs)
- Application-layer threats (this is a platform/infra security exercise,
  not an AppSec one)
- Identity federation / SSO threats
