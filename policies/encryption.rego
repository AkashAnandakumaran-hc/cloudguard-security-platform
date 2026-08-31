package cloudguard.encryption

# SEC-003: All storage (S3, EBS) must be encrypted at rest.

deny[msg] {
    resource := input.resource.aws_ebs_volume[name]
    resource.encrypted == false
    msg := sprintf("SEC-003 violation: EBS volume '%s' is not encrypted", [name])
}

deny[msg] {
    resource := input.resource.aws_s3_bucket[name]
    not input.resource.aws_s3_bucket_server_side_encryption_configuration[name]
    msg := sprintf("SEC-003 violation: S3 bucket '%s' has no server-side encryption configuration", [name])
}
