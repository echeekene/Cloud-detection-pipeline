mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/cloud-detection-log-processor" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-1:111122223333:cloud-detection-processing-failures" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:111122223333:function:cloud-detection-process-logs" }
  }
}

variables {
  expected_account_id  = "111122223333"
  reserved_concurrency = 1
  package = {
    path         = "mock-package.zip"
    sha256       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    base64sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  }
}

run "shared_capacity_for_small_account_quota" {
  command = plan
  variables { reserved_concurrency = -1 }
  assert {
    condition     = aws_lambda_function.processor.reserved_concurrent_executions == -1
    error_message = "Small accounts must be able to use shared capacity without requesting a quota increase."
  }
}

run "disabled_until_verified" {
  command = apply
  assert {
    condition     = length(aws_s3_bucket_notification.raw_delivery) == 0 && aws_lambda_function.processor.reserved_concurrent_executions == 1 && aws_lambda_function.processor.timeout == 60
    error_message = "Keep automatic triggers off until checked and bound runtime and concurrency."
  }
  assert {
    condition     = aws_cloudwatch_log_group.processor.retention_in_days == 3 && aws_sqs_queue.failures.message_retention_seconds == 86400 && aws_sqs_queue.failures.sqs_managed_sse_enabled
    error_message = "Logs and failed invocations need short, encrypted retention."
  }
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.processor.policy).Statement[0].Resource == "arn:aws:s3:::cloud-detection-111122223333-us-east-1-raw/cloudtrail/AWSLogs/111122223333/CloudTrail/*" &&
      jsondecode(aws_iam_role_policy.processor.policy).Statement[1].Resource == "arn:aws:s3:::cloud-detection-111122223333-us-east-1-analytics/automated/*" &&
      aws_lambda_permission.raw_delivery.source_account == "111122223333"
    )
    error_message = "Restrict the runtime to project log input and automated output."
  }
  assert {
    condition     = aws_glue_catalog_table.automated.name == "automated_events" && aws_glue_catalog_table.automated.parameters["projection.region.type"] == "injected"
    error_message = "Keep automated data separate and require region filters for projected queries."
  }
}

run "explicit_filtered_trigger" {
  command = apply
  variables { enable_notifications = true }
  assert {
    condition = (
      one(aws_s3_bucket_notification.raw_delivery[0].lambda_function).filter_prefix == "cloudtrail/AWSLogs/111122223333/CloudTrail/" &&
      one(aws_s3_bucket_notification.raw_delivery[0].lambda_function).filter_suffix == ".json.gz" &&
      aws_lambda_function_event_invoke_config.processor.maximum_retry_attempts == 1
    )
    error_message = "Exclude digest files and unrelated writes and bound asynchronous retries."
  }
}
