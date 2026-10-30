mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/cloud-detection-alert-runner" }
  }
  mock_resource "aws_sqs_queue" {
    defaults = { arn = "arn:aws:sqs:us-east-1:111122223333:cloud-detection-alert-failures" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:us-east-1:111122223333:table/cloud-detection-alert-dedupe" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:111122223333:function:cloud-detection-alert-runner" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:us-east-1:111122223333:rule/cloud-detection-alert-runner-schedule" }
  }
}

variables {
  expected_account_id = "111122223333"
  package = {
    path         = "mock-alerts-package.zip"
    sha256       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    base64sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  }
}

run "scheduled_every_fifteen_minutes_and_bounded" {
  command = apply
  assert {
    condition     = aws_cloudwatch_event_rule.schedule.schedule_expression == "rate(15 minutes)" && aws_cloudwatch_event_rule.schedule.state == "ENABLED"
    error_message = "Detections must run every 15 minutes while enabled."
  }
  assert {
    condition     = aws_lambda_function.runner.timeout == 120 && aws_lambda_function_event_invoke_config.runner.maximum_retry_attempts == 0
    error_message = "Bound runtime; overlapping lookback replaces retries."
  }
  assert {
    condition     = aws_dynamodb_table.dedupe.billing_mode == "PAY_PER_REQUEST" && one(aws_dynamodb_table.dedupe.ttl).enabled
    error_message = "Dedupe records must expire and cost nothing when idle."
  }
}

run "least_privilege_runtime" {
  command = apply
  assert {
    condition = (
      !strcontains(aws_iam_role_policy.runner.policy, "ssm:PutParameter") &&
      !strcontains(aws_iam_role_policy.runner.policy, "dynamodb:DeleteItem") &&
      !strcontains(aws_iam_role_policy.runner.policy, "glue:Create") &&
      strcontains(aws_iam_role_policy.runner.policy, "parameter/cloud-detection/slack-webhook")
    )
    error_message = "The runner may only read the webhook, query events, and record sent alerts."
  }
}

run "daily_scorecard" {
  command = apply
  assert {
    condition     = aws_cloudwatch_event_rule.scorecard.schedule_expression == "cron(5 14 * * ? *)" && jsondecode(aws_cloudwatch_event_target.scorecard.input).scorecard
    error_message = "The scorecard must run once a day with the scorecard input."
  }
}

run "pause_through_terraform" {
  command = apply
  variables { enabled = false }
  assert {
    condition     = aws_cloudwatch_event_rule.schedule.state == "DISABLED" && aws_cloudwatch_event_rule.scorecard.state == "DISABLED"
    error_message = "Pausing must be possible without drift."
  }
}
