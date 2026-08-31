package cloudguard.network

# SEC-002: Administrative ports must never be reachable from 0.0.0.0/0.
# This encodes the same control Checkov enforces (CKV_AWS_24) as an
# explicit, human-readable organizational policy, independent of any
# single scanner's ruleset -- the point being that the RULE is owned
# by the security team, not by whichever tool happens to implement it.

admin_ports := {22, 3389}

deny[msg] {
    some resource
    resource := input.resource.aws_security_group[name]
    some rule
    rule := resource.ingress[_]
    rule.cidr_blocks[_] == "0.0.0.0/0"
    admin_ports[rule.from_port]
    msg := sprintf(
        "SEC-002 violation: security group '%s' exposes admin port %v to 0.0.0.0/0",
        [name, rule.from_port],
    )
}
