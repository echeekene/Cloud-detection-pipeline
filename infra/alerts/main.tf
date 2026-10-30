terraform {
  required_version = ">= 1.11.0, < 2.0.0"
  # Shared settings come from infra/backend.hcl; see docs/STATE.md.
  backend "s3" {
    key = "alerts/terraform.tfstate"
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

variable "package" {
  description = "Output of scripts/build_api_package.py --target alerts."
  type        = object({ path = string, sha256 = string, base64sha256 = string })
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.package.sha256)) && can(regex("^[A-Za-z0-9+/]{43}=$", var.package.base64sha256))
    error_message = "Provide the package's hex and base64 SHA256 checksums."
  }
}

variable "enabled" {
  description = "Set false to pause scheduled detections through Terraform instead of out-of-band changes."
  type        = bool
  default     = true
}

variable "regions" {
  description = "Regions whose automated_events partitions are checked. Global services such as IAM and sign-in log to us-east-1."
  type        = list(string)
  default     = ["us-east-1"]
  validation {
    condition     = length(var.regions) > 0 && alltrue([for r in var.regions : can(regex("^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$", r))])
    error_message = "Provide at least one valid AWS region."
  }
}

variable "webhook_parameter_name" {
  description = "SecureString holding the Slack webhook. Created outside Terraform so the secret never enters state."
  type        = string
  default     = "/cloud-detection/slack-webhook"
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = [var.expected_account_id]
  default_tags { tags = { Project = "cloud-detection", Purpose = "scheduled-detection-alerts" } }
}

locals {
  name             = "cloud-detection-alert-runner"
  analytics_bucket = "cloud-detection-${var.expected_account_id}-us-east-1-analytics"
  bucket_arn       = "arn:aws:s3:::${local.analytics_bucket}"
  workgroup        = "cloud-detection-queries"
  log_group        = "/aws/lambda/${local.name}"
}

resource "aws_dynamodb_table" "dedupe" {
  name         = "cloud-detection-alert-dedupe"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "finding_key"
  attribute {
    name = "finding_key"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

resource "aws_cloudwatch_log_group" "runner" {
  name              = local.log_group
  retention_in_days = 7
}

resource "aws_sqs_queue" "failures" {
  name                      = "cloud-detection-alert-failures"
  message_retention_seconds = 345600
  sqs_managed_sse_enabled   = true
}

resource "aws_iam_role" "runner" {
  name = local.name
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "runner" {
  role = aws_iam_role.runner.id
  name = "scheduled-detection-queries"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution"]
        Resource = "arn:aws:athena:us-east-1:${var.expected_account_id}:workgroup/${local.workgroup}"
      },
      {
        Effect = "Allow"
        Action = ["glue:GetDatabase", "glue:GetTable", "glue:GetPartition", "glue:GetPartitions"]
        Resource = [
          "arn:aws:glue:us-east-1:${var.expected_account_id}:catalog",
          "arn:aws:glue:us-east-1:${var.expected_account_id}:database/cloud_detection",
          "arn:aws:glue:us-east-1:${var.expected_account_id}:table/cloud_detection/automated_events"
        ]
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = "${local.bucket_arn}/automated/parquet/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "${local.bucket_arn}/athena-results/*"
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetBucketLocation"]
        Resource = local.bucket_arn
      },
      {
        Effect    = "Allow"
        Action    = ["s3:ListBucket"]
        Resource  = local.bucket_arn
        Condition = { StringLike = { "s3:prefix" = ["automated/parquet/*", "athena-results/*"] } }
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem"]
        Resource = aws_dynamodb_table.dedupe.arn
      },
      {
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = "arn:aws:ssm:us-east-1:${var.expected_account_id}:parameter${var.webhook_parameter_name}"
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:us-east-1:${var.expected_account_id}:log-group:${local.log_group}:*"
      },
      {
        Effect   = "Allow"
        Action   = ["sqs:SendMessage"]
        Resource = aws_sqs_queue.failures.arn
      }
    ]
  })
}

resource "aws_lambda_function" "runner" {
  function_name    = local.name
  description      = "Run detections over recent events every 15 minutes and alert Slack once per finding."
  role             = aws_iam_role.runner.arn
  runtime          = "python3.12"
  handler          = "cloud_detection.alerting.handler"
  architectures    = ["x86_64"]
  memory_size      = 256
  timeout          = 120
  filename         = var.package.path
  source_code_hash = var.package.base64sha256
  environment {
    variables = {
      ATHENA_WORKGROUP      = local.workgroup
      DEDUPE_TABLE          = aws_dynamodb_table.dedupe.name
      WEBHOOK_PARAMETER     = var.webhook_parameter_name
      REGIONS               = join(",", var.regions)
      LOOKBACK_MINUTES      = "90"
      QUERY_TIMEOUT_SECONDS = "60"
    }
  }
  depends_on = [aws_cloudwatch_log_group.runner, aws_iam_role_policy.runner]
}

# A failed run is not retried: the next run's 90-minute lookback covers the gap.
resource "aws_lambda_function_event_invoke_config" "runner" {
  function_name                = aws_lambda_function.runner.function_name
  maximum_retry_attempts       = 0
  maximum_event_age_in_seconds = 900
  destination_config {
    on_failure { destination = aws_sqs_queue.failures.arn }
  }
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.name}-schedule"
  description         = "Run scheduled detections every 15 minutes."
  schedule_expression = "rate(15 minutes)"
  state               = var.enabled ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "runner" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.runner.arn
}

resource "aws_lambda_permission" "schedule" {
  statement_id  = "AllowScheduledRuns"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.runner.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

output "function_name" { value = aws_lambda_function.runner.function_name }
output "failure_queue_url" { value = aws_sqs_queue.failures.url }
output "schedule_state" { value = aws_cloudwatch_event_rule.schedule.state }
