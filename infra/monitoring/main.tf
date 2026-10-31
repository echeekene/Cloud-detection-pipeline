terraform {
  required_version = ">= 1.11.0, < 2.0.0"
  # Shared settings come from infra/backend.hcl; see docs/STATE.md.
  backend "s3" {
    key = "monitoring/terraform.tfstate"
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

variable "expected_account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Use the expected 12-digit account ID."
  }
}

variable "alert_email" {
  description = "Optional backup channel in case the Slack path itself fails. AWS sends a confirmation email first."
  type        = string
  default     = ""
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = [var.expected_account_id]
  default_tags { tags = { Project = "cloud-detection", Purpose = "pipeline-health" } }
}

locals {
  prefix       = "cloud-detection"
  alert_runner = "cloud-detection-alert-runner"
  runner_arn   = "arn:aws:lambda:us-east-1:${var.expected_account_id}:function:${local.alert_runner}"

  # Each alarm: what it watches, and whether missing data means trouble.
  lambda_errors = {
    "processor-errors"    = { function = "cloud-detection-process-logs", description = "The log processor Lambda failed while turning CloudTrail files into Parquet." }
    "alert-runner-errors" = { function = local.alert_runner, description = "The scheduled detection runner failed, so findings may not reach Slack." }
    "simulator-errors"    = { function = "cloud-detection-attack-simulator", description = "An attack simulation failed to run or restore its canary setting." }
  }
  queues = {
    "processing-failures-queued" = { queue = "cloud-detection-processing-failures", description = "Failed log processing events are waiting in the processor's failure queue." }
    "alert-failures-queued"      = { queue = "cloud-detection-alert-failures", description = "Failed detection runs are waiting in the alert runner's failure queue." }
  }
}

data "aws_apigatewayv2_apis" "findings" {
  name          = "cloud-detection-findings-api"
  protocol_type = "HTTP"
}

# CloudWatch alarms cannot publish to topics encrypted with the AWS managed SNS key, and a customer
# key costs extra, so this topic is unencrypted. Messages hold alarm metadata only, never log data.
resource "aws_sns_topic" "health" {
  name = "${local.prefix}-health"
}

resource "aws_sns_topic_policy" "health" {
  arn = aws_sns_topic.health.arn
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "AllowCloudWatchAlarmsFromThisAccount"
      Effect    = "Allow"
      Principal = { Service = "cloudwatch.amazonaws.com" }
      Action    = "sns:Publish"
      Resource  = aws_sns_topic.health.arn
      Condition = { StringEquals = { "aws:SourceAccount" = var.expected_account_id } }
    }]
  })
}

resource "aws_sns_topic_subscription" "slack" {
  topic_arn = aws_sns_topic.health.arn
  protocol  = "lambda"
  endpoint  = local.runner_arn
}

resource "aws_lambda_permission" "sns" {
  statement_id  = "AllowHealthAlarms"
  action        = "lambda:InvokeFunction"
  function_name = local.alert_runner
  principal     = "sns.amazonaws.com"
  source_arn    = aws_sns_topic.health.arn
}

resource "aws_sns_topic_subscription" "email" {
  count     = var.alert_email == "" ? 0 : 1
  topic_arn = aws_sns_topic.health.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors" {
  for_each            = local.lambda_errors
  alarm_name          = "${local.prefix}-${each.key}"
  alarm_description   = each.value.description
  namespace           = "AWS/Lambda"
  metric_name         = "Errors"
  dimensions          = { FunctionName = each.value.function }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.health.arn]
  ok_actions          = [aws_sns_topic.health.arn]
}

resource "aws_cloudwatch_metric_alarm" "queues" {
  for_each            = local.queues
  alarm_name          = "${local.prefix}-${each.key}"
  alarm_description   = each.value.description
  namespace           = "AWS/SQS"
  metric_name         = "ApproximateNumberOfMessagesVisible"
  dimensions          = { QueueName = each.value.queue }
  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.health.arn]
  ok_actions          = [aws_sns_topic.health.arn]
}

# Heartbeat: the runner is scheduled every 15 minutes, so a silent hour means the schedule or function is broken.
resource "aws_cloudwatch_metric_alarm" "alert_runner_silent" {
  alarm_name          = "${local.prefix}-alert-runner-silent"
  alarm_description   = "The detection runner has not run in an hour, so new findings are not being checked."
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  dimensions          = { FunctionName = local.alert_runner }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.health.arn]
  ok_actions          = [aws_sns_topic.health.arn]
}

# Log freshness: the runner's own Athena calls create CloudTrail events every 15 minutes, so two hours
# without a processed log file means delivery, the S3 trigger, or logging itself has stopped.
resource "aws_cloudwatch_metric_alarm" "logs_stale" {
  alarm_name          = "${local.prefix}-logs-stale"
  alarm_description   = "No CloudTrail log file has been processed for two hours. Check trail logging and the S3 trigger."
  namespace           = "AWS/Lambda"
  metric_name         = "Invocations"
  dimensions          = { FunctionName = "cloud-detection-process-logs" }
  statistic           = "Sum"
  period              = 3600
  evaluation_periods  = 2
  datapoints_to_alarm = 2
  threshold           = 1
  comparison_operator = "LessThanThreshold"
  treat_missing_data  = "breaching"
  alarm_actions       = [aws_sns_topic.health.arn]
  ok_actions          = [aws_sns_topic.health.arn]
}

resource "aws_cloudwatch_metric_alarm" "api_5xx" {
  alarm_name          = "${local.prefix}-api-5xx"
  alarm_description   = "The findings API returned server errors, usually a failed or timed out Athena query."
  namespace           = "AWS/ApiGateway"
  metric_name         = "5xx"
  dimensions          = { ApiId = one(data.aws_apigatewayv2_apis.findings.ids) }
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 0
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.health.arn]
  ok_actions          = [aws_sns_topic.health.arn]
}

output "topic_arn" { value = aws_sns_topic.health.arn }
output "alarm_names" {
  value = concat([for a in aws_cloudwatch_metric_alarm.lambda_errors : a.alarm_name], [for a in aws_cloudwatch_metric_alarm.queues : a.alarm_name],
  [aws_cloudwatch_metric_alarm.alert_runner_silent.alarm_name, aws_cloudwatch_metric_alarm.logs_stale.alarm_name, aws_cloudwatch_metric_alarm.api_5xx.alarm_name])
}
