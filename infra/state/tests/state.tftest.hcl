mock_provider "aws" {}

variables {
  expected_account_id = "111122223333"
}

run "state_bucket_is_private_versioned_and_encrypted" {
  command = apply
  assert {
    condition     = aws_s3_bucket.state.bucket == "cloud-detection-111122223333-us-east-1-tfstate" && !aws_s3_bucket.state.force_destroy
    error_message = "State must use the expected name and must not be deletable by default."
  }
  assert {
    condition     = aws_s3_bucket_versioning.state.versioning_configuration[0].status == "Enabled"
    error_message = "Versioning is required so earlier state can be recovered."
  }
  assert {
    condition = (
      aws_s3_bucket_public_access_block.state.block_public_acls && aws_s3_bucket_public_access_block.state.block_public_policy &&
      aws_s3_bucket_public_access_block.state.ignore_public_acls && aws_s3_bucket_public_access_block.state.restrict_public_buckets
    )
    error_message = "State can contain sensitive values and must never be public."
  }
  assert {
    condition     = one(one(aws_s3_bucket_server_side_encryption_configuration.state.rule).apply_server_side_encryption_by_default).sse_algorithm == "AES256"
    error_message = "State must be encrypted at rest."
  }
  assert {
    condition     = jsondecode(aws_s3_bucket_policy.state.policy).Statement[0].Condition.Bool["aws:SecureTransport"] == "false"
    error_message = "Requests without TLS must be denied."
  }
}
