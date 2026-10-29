mock_provider "aws" {
  mock_data "aws_partition" {
    defaults = { partition = "aws" }
  }
}

variables {
  expected_account_id = "111122223333"
}

run "secure_foundation" {
  command = plan

  assert {
    condition = (
      aws_s3_bucket_public_access_block.raw.block_public_acls &&
      aws_s3_bucket_public_access_block.raw.block_public_policy &&
      aws_s3_bucket_public_access_block.raw.ignore_public_acls &&
      aws_s3_bucket_public_access_block.raw.restrict_public_buckets &&
      aws_s3_bucket_ownership_controls.raw.rule[0].object_ownership == "BucketOwnerEnforced"
    )
    error_message = "Logs must have public access blocked and bucket-owner ownership."
  }

  assert {
    condition = (
      !aws_s3_bucket.raw.force_destroy &&
      aws_s3_bucket_versioning.raw.versioning_configuration[0].status == "Enabled" &&
      one(aws_s3_bucket_server_side_encryption_configuration.raw.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"
    )
    error_message = "Default settings must retain deletion protection, versioning, and encryption."
  }

  assert {
    condition = (
      aws_cloudtrail.audit.is_multi_region_trail &&
      aws_cloudtrail.audit.include_global_service_events &&
      aws_cloudtrail.audit.enable_logging &&
      aws_cloudtrail.audit.enable_log_file_validation &&
      one(aws_cloudtrail.audit.event_selector).include_management_events &&
      one(aws_cloudtrail.audit.event_selector).read_write_type == "All"
    )
    error_message = "The trail must collect all management events across regions and enable validation."
  }

  assert {
    condition = (
      local.bucket_policy.Statement[0].Effect == "Deny" &&
      local.bucket_policy.Statement[0].Condition.Bool["aws:SecureTransport"] == "false" &&
      local.bucket_policy.Statement[1].Condition.StringEquals["aws:SourceArn"] == "arn:aws:cloudtrail:us-east-1:111122223333:trail/cloud-detection-audit" &&
      local.bucket_policy.Statement[2].Condition.StringEquals["aws:SourceArn"] == local.trail_arn &&
      local.bucket_policy.Statement[2].Condition.StringEquals["s3:x-amz-acl"] == "bucket-owner-full-control" &&
      local.bucket_policy.Statement[2].Resource == "arn:aws:s3:::cloud-detection-111122223333-us-east-1-raw/cloudtrail/AWSLogs/111122223333/*"
    )
    error_message = "Delivery must require the named trail, expected account prefix, and HTTPS."
  }
}

run "reject_invalid_account" {
  command = plan
  variables { expected_account_id = "not-an-account" }
  expect_failures = [var.expected_account_id]
}

run "reject_short_retention" {
  command = plan
  variables { log_retention_days = 0 }
  expect_failures = [var.log_retention_days]
}

run "explicit_teardown_opt_in" {
  command = plan
  variables { allow_log_deletion = true }
  assert {
    condition     = aws_s3_bucket.raw.force_destroy
    error_message = "Lab log deletion must require an explicit opt-in."
  }
}
