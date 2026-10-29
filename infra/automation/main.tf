terraform {
  required_version = ">= 1.9.0, < 2.0.0"
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
  type = object({ path = string, sha256 = string, base64sha256 = string })
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.package.sha256)) && can(regex("^[A-Za-z0-9+/]{43}=$", var.package.base64sha256))
    error_message = "Provide the package's hex and base64 SHA256 checksums."
  }
}

variable "enable_notifications" {
  description = "Enable only after checking the existing bucket notification configuration and deployed function."
  type        = bool
  default     = false
}

variable "reserved_concurrency" {
  description = "Use -1 for shared account capacity when the account quota cannot support a reservation; 0 pauses execution, 1 limits it where supported."
  type        = number
  default     = -1
  validation {
    condition     = contains([-1, 0, 1], var.reserved_concurrency)
    error_message = "Use shared capacity (-1), a paused function (0), or one reserved execution (1)."
  }
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = [var.expected_account_id]
  default_tags { tags = { Project = "cloud-detection", Purpose = "automatic-log-processing" } }
}

locals {
  raw_bucket       = "cloud-detection-${var.expected_account_id}-us-east-1-raw"
  analytics_bucket = "cloud-detection-${var.expected_account_id}-us-east-1-analytics"
  raw_prefix       = "cloudtrail/AWSLogs/${var.expected_account_id}/CloudTrail/"
  function_name    = "cloud-detection-process-logs"
  log_group        = "/aws/lambda/${local.function_name}"
  role_name        = "cloud-detection-log-processor"
  columns          = jsondecode(file("${path.module}/../analytics/columns.json"))
}

resource "aws_s3_object" "package" {
  bucket                 = local.analytics_bucket
  key                    = "deployment/lambda/${var.package.sha256}.zip"
  source                 = var.package.path
  source_hash            = var.package.sha256
  server_side_encryption = "AES256"
}

resource "aws_cloudwatch_log_group" "processor" {
  name              = local.log_group
  retention_in_days = 3
}

resource "aws_sqs_queue" "failures" {
  name                      = "cloud-detection-processing-failures"
  message_retention_seconds = 86400
  sqs_managed_sse_enabled   = true
}

resource "aws_iam_role" "processor" {
  name = local.role_name
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

resource "aws_iam_role_policy" "processor" {
  role = aws_iam_role.processor.id
  name = "bounded-log-processing"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject", "s3:GetObjectVersion"], Resource = "arn:aws:s3:::${local.raw_bucket}/${local.raw_prefix}*" },
      { Effect = "Allow", Action = ["s3:GetObject", "s3:PutObject"], Resource = "arn:aws:s3:::${local.analytics_bucket}/automated/*" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = "arn:aws:s3:::${local.analytics_bucket}", Condition = { StringLike = { "s3:prefix" = ["automated/runs/*"] } } },
      { Effect = "Allow", Action = ["logs:CreateLogStream", "logs:PutLogEvents"], Resource = "arn:aws:logs:us-east-1:${var.expected_account_id}:log-group:${local.log_group}:*" },
      { Effect = "Allow", Action = ["sqs:SendMessage"], Resource = aws_sqs_queue.failures.arn }
    ]
  })
}

resource "aws_lambda_function" "processor" {
  function_name                  = local.function_name
  description                    = "Normalize newly delivered CloudTrail objects into bounded Parquet output."
  role                           = aws_iam_role.processor.arn
  runtime                        = "python3.12"
  handler                        = "cloud_detection.lambda_handler.handler"
  architectures                  = ["x86_64"]
  memory_size                    = 512
  timeout                        = 60
  reserved_concurrent_executions = var.reserved_concurrency
  s3_bucket                      = aws_s3_object.package.bucket
  s3_key                         = aws_s3_object.package.key
  s3_object_version              = aws_s3_object.package.version_id
  source_code_hash               = var.package.base64sha256
  environment {
    variables = {
      RAW_BUCKET       = local.raw_bucket
      ANALYTICS_BUCKET = local.analytics_bucket
      INPUT_PREFIX     = local.raw_prefix
    }
  }
  depends_on = [aws_cloudwatch_log_group.processor, aws_iam_role_policy.processor]
}

resource "aws_lambda_function_event_invoke_config" "processor" {
  function_name                = aws_lambda_function.processor.function_name
  maximum_event_age_in_seconds = 3600
  maximum_retry_attempts       = 1
  destination_config {
    on_failure { destination = aws_sqs_queue.failures.arn }
  }
}

resource "aws_lambda_permission" "raw_delivery" {
  statement_id   = "AllowProjectCloudTrailObjects"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.processor.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = "arn:aws:s3:::${local.raw_bucket}"
  source_account = var.expected_account_id
}

# One owner must manage all bucket notifications. Preflight must reject an existing unrelated configuration.
resource "aws_s3_bucket_notification" "raw_delivery" {
  count  = var.enable_notifications ? 1 : 0
  bucket = local.raw_bucket
  lambda_function {
    lambda_function_arn = aws_lambda_function.processor.arn
    events              = ["s3:ObjectCreated:*"]
    filter_prefix       = local.raw_prefix
    filter_suffix       = ".json.gz"
  }
  depends_on = [aws_lambda_permission.raw_delivery, aws_lambda_function_event_invoke_config.processor]
}

resource "aws_glue_catalog_table" "automated" {
  catalog_id    = var.expected_account_id
  database_name = "cloud_detection"
  name          = "automated_events"
  table_type    = "EXTERNAL_TABLE"
  parameters = {
    EXTERNAL                       = "TRUE"
    classification                 = "parquet"
    "projection.enabled"           = "true"
    "projection.event_date.type"   = "date"
    "projection.event_date.range"  = "2020-01-01,NOW"
    "projection.event_date.format" = "yyyy-MM-dd"
    "projection.region.type"       = "injected"
    "storage.location.template"    = "s3://${local.analytics_bucket}/automated/parquet/event_date=$${event_date}/region=$${region}/"
  }
  storage_descriptor {
    location      = "s3://${local.analytics_bucket}/automated/parquet/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
    ser_de_info { serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe" }
    dynamic "columns" {
      for_each = local.columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
  partition_keys {
    name = "event_date"
    type = "string"
  }
  partition_keys {
    name = "region"
    type = "string"
  }
}

output "function_name" { value = aws_lambda_function.processor.function_name }
output "automated_table" { value = "cloud_detection.automated_events" }
output "failure_queue_url" { value = aws_sqs_queue.failures.url }
output "notifications_enabled" { value = var.enable_notifications }
