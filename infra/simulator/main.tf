terraform {
  required_version = ">= 1.11.0, < 2.0.0"
  # Shared settings come from infra/backend.hcl; see docs/STATE.md.
  backend "s3" {
    key = "simulator/terraform.tfstate"
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
  description = "Output of scripts/build_api_package.py --target simulator."
  type        = object({ path = string, sha256 = string, base64sha256 = string })
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.package.sha256)) && can(regex("^[A-Za-z0-9+/]{43}=$", var.package.base64sha256))
    error_message = "Provide the package's hex and base64 SHA256 checksums."
  }
}

variable "enabled" {
  description = "Set false to stop scheduled simulations through Terraform."
  type        = bool
  default     = true
}

variable "schedule" {
  description = "How often to run one random simulation."
  type        = string
  default     = "rate(6 hours)"
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = [var.expected_account_id]
  default_tags { tags = { Project = "cloud-detection", Purpose = "attack-simulation" } }
}

locals {
  name          = "cloud-detection-attack-simulator"
  log_group     = "/aws/lambda/${local.name}"
  canary_bucket = "cloud-detection-${var.expected_account_id}-us-east-1-canary"
  trail_arn     = "arn:aws:cloudtrail:us-east-1:${var.expected_account_id}:trail/cloud-detection-audit"
}

# Canary user: no password, no standing keys, no permissions. Only the simulator touches it.
resource "aws_iam_user" "canary" {
  name          = "cloud-detection-canary"
  force_destroy = true
}

# Attached for two seconds per simulation. Denies everything, so attaching it can only reduce access.
resource "aws_iam_policy" "canary_deny_all" {
  name        = "cloud-detection-canary-deny-all"
  description = "Harmless policy the attack simulator attaches and detaches to trigger detection."
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Deny", Action = "*", Resource = "*" }]
  })
}

# Empty bucket whose public access block is briefly removed. It never holds data or a bucket policy.
resource "aws_s3_bucket" "canary" {
  bucket        = local.canary_bucket
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "canary" {
  bucket                  = aws_s3_bucket.canary.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "canary" {
  bucket = aws_s3_bucket.canary.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_dynamodb_table" "simulations" {
  name         = "cloud-detection-simulations"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "sim_id"
  attribute {
    name = "sim_id"
    type = "S"
  }
  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }
}

resource "aws_cloudwatch_log_group" "simulator" {
  name              = local.log_group
  retention_in_days = 7
}

resource "aws_iam_role" "simulator" {
  name = local.name
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "simulator" {
  role = aws_iam_role.simulator.id
  name = "reversible-canary-actions"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreateAccessKey", "iam:DeleteAccessKey"]
        Resource = aws_iam_user.canary.arn
      },
      {
        Effect    = "Allow"
        Action    = ["iam:AttachUserPolicy", "iam:DetachUserPolicy"]
        Resource  = aws_iam_user.canary.arn
        Condition = { ArnEquals = { "iam:PolicyARN" = aws_iam_policy.canary_deny_all.arn } }
      },
      {
        # Covers both deleting and restoring the bucket's public access block.
        Effect   = "Allow"
        Action   = ["s3:PutBucketPublicAccessBlock"]
        Resource = aws_s3_bucket.canary.arn
      },
      {
        Effect   = "Allow"
        Action   = ["cloudtrail:StopLogging", "cloudtrail:StartLogging"]
        Resource = local.trail_arn
      },
      {
        Effect   = "Allow"
        Action   = ["dynamodb:PutItem", "dynamodb:UpdateItem"]
        Resource = aws_dynamodb_table.simulations.arn
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:us-east-1:${var.expected_account_id}:log-group:${local.log_group}:*"
      }
    ]
  })
}

resource "aws_lambda_function" "simulator" {
  function_name    = local.name
  description      = "Run one harmless, reversible action that a detection rule should catch."
  role             = aws_iam_role.simulator.arn
  runtime          = "python3.12"
  handler          = "cloud_detection.simulator.handler"
  architectures    = ["x86_64"]
  memory_size      = 128
  timeout          = 60
  filename         = var.package.path
  source_code_hash = var.package.base64sha256
  environment {
    variables = {
      SIMULATIONS_TABLE = aws_dynamodb_table.simulations.name
      CANARY_USER       = aws_iam_user.canary.name
      CANARY_POLICY_ARN = aws_iam_policy.canary_deny_all.arn
      CANARY_BUCKET     = aws_s3_bucket.canary.id
      TRAIL_NAME        = "cloud-detection-audit"
    }
  }
  depends_on = [aws_cloudwatch_log_group.simulator, aws_iam_role_policy.simulator, aws_s3_bucket_public_access_block.canary]
}

resource "aws_lambda_function_event_invoke_config" "simulator" {
  function_name          = aws_lambda_function.simulator.function_name
  maximum_retry_attempts = 0
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.name}-schedule"
  description         = "Run one random attack simulation."
  schedule_expression = var.schedule
  state               = var.enabled ? "ENABLED" : "DISABLED"
}

resource "aws_cloudwatch_event_target" "simulator" {
  rule = aws_cloudwatch_event_rule.schedule.name
  arn  = aws_lambda_function.simulator.arn
}

resource "aws_lambda_permission" "schedule" {
  statement_id  = "AllowScheduledSimulations"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.simulator.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

output "function_name" { value = aws_lambda_function.simulator.function_name }
output "simulations_table" { value = aws_dynamodb_table.simulations.name }
output "schedule_state" { value = aws_cloudwatch_event_rule.schedule.state }
