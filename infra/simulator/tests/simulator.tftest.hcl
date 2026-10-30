mock_provider "aws" {
  mock_resource "aws_iam_user" {
    defaults = { arn = "arn:aws:iam::111122223333:user/cloud-detection-canary" }
  }
  mock_resource "aws_iam_policy" {
    defaults = { arn = "arn:aws:iam::111122223333:policy/cloud-detection-canary-deny-all" }
  }
  mock_resource "aws_s3_bucket" {
    defaults = {
      id  = "cloud-detection-111122223333-us-east-1-canary"
      arn = "arn:aws:s3:::cloud-detection-111122223333-us-east-1-canary"
    }
  }
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/cloud-detection-attack-simulator" }
  }
  mock_resource "aws_dynamodb_table" {
    defaults = { arn = "arn:aws:dynamodb:us-east-1:111122223333:table/cloud-detection-simulations" }
  }
  mock_resource "aws_lambda_function" {
    defaults = { arn = "arn:aws:lambda:us-east-1:111122223333:function:cloud-detection-attack-simulator" }
  }
  mock_resource "aws_cloudwatch_event_rule" {
    defaults = { arn = "arn:aws:events:us-east-1:111122223333:rule/cloud-detection-attack-simulator-schedule" }
  }
}

variables {
  expected_account_id = "111122223333"
  package = {
    path         = "mock-simulator-package.zip"
    sha256       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    base64sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  }
}

run "canary_resources_are_harmless" {
  command = apply
  assert {
    condition     = jsondecode(aws_iam_policy.canary_deny_all.policy).Statement[0].Effect == "Deny"
    error_message = "The attachable canary policy must only deny."
  }
  assert {
    condition     = aws_s3_bucket_public_access_block.canary.block_public_policy && aws_s3_bucket_public_access_block.canary.restrict_public_buckets
    error_message = "The canary bucket's resting state must block public access."
  }
}

run "simulator_can_only_touch_canaries_and_the_project_trail" {
  command = apply
  assert {
    condition = (
      jsondecode(aws_iam_role_policy.simulator.policy).Statement[0].Resource == "arn:aws:iam::111122223333:user/cloud-detection-canary" &&
      jsondecode(aws_iam_role_policy.simulator.policy).Statement[1].Condition.ArnEquals["iam:PolicyARN"] == "arn:aws:iam::111122223333:policy/cloud-detection-canary-deny-all" &&
      jsondecode(aws_iam_role_policy.simulator.policy).Statement[3].Resource == "arn:aws:cloudtrail:us-east-1:111122223333:trail/cloud-detection-audit" &&
      !strcontains(aws_iam_role_policy.simulator.policy, "\"*\"")
    )
    error_message = "Simulator permissions must be scoped to canary resources and the project trail."
  }
}

run "schedule_can_be_paused_through_terraform" {
  command = apply
  variables { enabled = false }
  assert {
    condition     = aws_cloudwatch_event_rule.schedule.state == "DISABLED" && aws_cloudwatch_event_rule.schedule.schedule_expression == "rate(6 hours)"
    error_message = "Simulations run every 6 hours by default and can be paused without drift."
  }
}
