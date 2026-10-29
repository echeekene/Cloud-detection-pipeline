mock_provider "aws" {
  mock_data "aws_partition" { defaults = { partition = "aws" } }
}

variables {
  expected_account_id = "111122223333"
  datasets = {
    security_events = {
      snapshot_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      partitions  = [{ event_date = "2026-01-01", region = "us-east-1" }]
    }
    synthetic_events = {
      snapshot_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
      partitions  = [{ event_date = "2026-01-01", region = "us-east-1" }]
    }
  }
}

run "bounded_queries_and_separate_samples" {
  command = apply
  assert {
    condition = (
      aws_athena_workgroup.queries.configuration[0].bytes_scanned_cutoff_per_query == 10485760 &&
      aws_athena_workgroup.queries.configuration[0].enforce_workgroup_configuration &&
      aws_athena_workgroup.queries.configuration[0].result_configuration[0].encryption_configuration[0].encryption_option == "SSE_S3" &&
      aws_athena_workgroup.queries.configuration[0].result_configuration[0].expected_bucket_owner == var.expected_account_id
    )
    error_message = "Our workgroup must enforce the scan limit and encrypted result settings."
  }
  assert {
    condition = (
      length(aws_glue_catalog_table.events) == 2 && length(aws_glue_partition.events) == 2 &&
      aws_glue_catalog_table.events["security_events"].parameters.sample_kind == "live" &&
      aws_glue_catalog_table.events["synthetic_events"].parameters.sample_kind == "synthetic" &&
      aws_glue_catalog_table.events["security_events"].storage_descriptor[0].location != aws_glue_catalog_table.events["synthetic_events"].storage_descriptor[0].location
    )
    error_message = "Real and synthetic logs must stay in separate tables and S3 locations."
  }
  assert {
    condition = (
      aws_s3_bucket_public_access_block.analytics.block_public_acls &&
      aws_s3_bucket_public_access_block.analytics.block_public_policy &&
      aws_s3_bucket_public_access_block.analytics.ignore_public_acls &&
      aws_s3_bucket_public_access_block.analytics.restrict_public_buckets &&
      !aws_s3_bucket.analytics.force_destroy &&
      one(aws_s3_bucket_server_side_encryption_configuration.analytics.rule).apply_server_side_encryption_by_default[0].sse_algorithm == "AES256"
    )
    error_message = "The analytics bucket must be private, encrypted, and resist accidental emptying."
  }
  assert {
    condition = (
      length(local.columns) == 12 &&
      jsondecode(output.analytics_access_policy).Statement[1].Resource == "arn:aws:athena:us-east-1:111122223333:workgroup/cloud-detection-queries"
    )
    error_message = "The schema and proposed access must match our project."
  }
}

run "reject_missing_synthetic_separation" {
  command = plan
  variables { datasets = {} }
  expect_failures = [var.datasets]
}

run "reject_wrong_account" {
  command = plan
  variables { expected_account_id = "invalid" }
  expect_failures = [var.expected_account_id]
}
