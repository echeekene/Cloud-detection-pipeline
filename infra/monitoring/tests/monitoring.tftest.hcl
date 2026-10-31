mock_provider "aws" {
  mock_resource "aws_sns_topic" {
    defaults = { arn = "arn:aws:sns:us-east-1:111122223333:cloud-detection-health" }
  }
  mock_data "aws_apigatewayv2_apis" {
    defaults = { ids = ["abc123"] }
  }
}

variables {
  expected_account_id = "111122223333"
}

run "every_alarm_notifies_on_problem_and_recovery" {
  command = apply
  assert {
    condition     = length(output.alarm_names) == 8
    error_message = "Expect eight health alarms."
  }
  assert {
    condition = alltrue([for a in concat(values(aws_cloudwatch_metric_alarm.lambda_errors), values(aws_cloudwatch_metric_alarm.queues)) :
    contains(a.alarm_actions, aws_sns_topic.health.arn) && contains(a.ok_actions, aws_sns_topic.health.arn) && a.alarm_description != ""])
    error_message = "Every alarm needs a description and must report both trouble and recovery."
  }
}

run "silence_is_treated_as_failure_for_heartbeats" {
  command = apply
  assert {
    condition     = aws_cloudwatch_metric_alarm.alert_runner_silent.treat_missing_data == "breaching" && aws_cloudwatch_metric_alarm.logs_stale.treat_missing_data == "breaching"
    error_message = "A stopped function produces no data, so missing data must alarm."
  }
  assert {
    condition     = aws_cloudwatch_metric_alarm.lambda_errors["processor-errors"].treat_missing_data == "notBreaching"
    error_message = "No errors reported means healthy for error alarms."
  }
}

run "only_this_accounts_cloudwatch_can_publish" {
  command = apply
  assert {
    condition     = jsondecode(aws_sns_topic_policy.health.policy).Statement[0].Condition.StringEquals["aws:SourceAccount"] == "111122223333"
    error_message = "Restrict topic publishing to CloudWatch in this account."
  }
  assert {
    condition     = length(aws_sns_topic_subscription.email) == 0
    error_message = "Email backup is opt in."
  }
}
