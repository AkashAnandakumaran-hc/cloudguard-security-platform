package cloudguard.iam

# SEC-005: No IAM policy statement may grant wildcard action or
# resource privileges. This is the org-level rule; Checkov's
# CKV_AWS_62/63/355 checks are the automated enforcement of it.

deny[msg] {
    policy := input.resource.aws_iam_policy[name]
    doc := json.unmarshal(policy.policy)
    stmt := doc.Statement[_]
    stmt.Effect == "Allow"
    action_is_wildcard(stmt.Action)
    msg := sprintf("SEC-005 violation: IAM policy '%s' allows wildcard action", [name])
}

action_is_wildcard(a) {
    a == "*"
}

action_is_wildcard(a) {
    a[_] == "*"
}
