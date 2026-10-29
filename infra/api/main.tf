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
  description = "Output of scripts/build_api_package.py."
  type        = object({ path = string, sha256 = string, base64sha256 = string })
  validation {
    condition     = can(regex("^[a-f0-9]{64}$", var.package.sha256)) && can(regex("^[A-Za-z0-9+/]{43}=$", var.package.base64sha256))
    error_message = "Provide the package's hex and base64 SHA256 checksums."
  }
}

variable "reserved_concurrency" {
  description = "Use -1 for shared account capacity, 0 to pause the API, or 1 to limit it where the account quota allows."
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
  default_tags { tags = { Project = "cloud-detection", Purpose = "read-only-findings-api" } }
}

locals {
  analytics_bucket = "cloud-detection-${var.expected_account_id}-us-east-1-analytics"
  bucket_arn       = "arn:aws:s3:::${local.analytics_bucket}"
  workgroup        = "cloud-detection-queries"
  function_name    = "cloud-detection-findings-api"
  log_group        = "/aws/lambda/${local.function_name}"
  tables           = ["security_events", "synthetic_events", "automated_events"]
  routes           = ["GET /findings", "GET /events", "GET /detections"]
}

locals {
  glue_resources = concat(
    ["arn:aws:glue:us-east-1:${var.expected_account_id}:catalog", "arn:aws:glue:us-east-1:${var.expected_account_id}:database/cloud_detection"],
    [for table in local.tables : "arn:aws:glue:us-east-1:${var.expected_account_id}:table/cloud_detection/${table}"]
  )
}

resource "aws_cloudwatch_log_group" "function" {
  name              = local.log_group
  retention_in_days = 3
}

resource "aws_cloudwatch_log_group" "access" {
  name              = "/aws/apigateway/${local.function_name}"
  retention_in_days = 3
}

resource "aws_iam_role" "api" {
  name = "cloud-detection-findings-reader"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "lambda.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

# Read-only access to the project tables plus the workgroup's own result prefix.
resource "aws_iam_role_policy" "api" {
  role = aws_iam_role.api.id
  name = "read-only-findings-queries"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults", "athena:StopQueryExecution"]
        Resource = "arn:aws:athena:us-east-1:${var.expected_account_id}:workgroup/${local.workgroup}"
      },
      {
        Effect   = "Allow"
        Action   = ["glue:GetDatabase", "glue:GetTable", "glue:GetPartition", "glue:GetPartitions"]
        Resource = local.glue_resources
      },
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject"]
        Resource = ["${local.bucket_arn}/datasets/*", "${local.bucket_arn}/automated/parquet/*"]
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
        Condition = { StringLike = { "s3:prefix" = ["datasets/*", "automated/parquet/*", "athena-results/*"] } }
      },
      {
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "arn:aws:logs:us-east-1:${var.expected_account_id}:log-group:${local.log_group}:*"
      }
    ]
  })
}

resource "aws_lambda_function" "api" {
  function_name                  = local.function_name
  description                    = "Validate findings API requests and run fixed, parameterized Athena queries."
  role                           = aws_iam_role.api.arn
  runtime                        = "python3.12"
  handler                        = "cloud_detection.api_handler.handler"
  architectures                  = ["x86_64"]
  memory_size                    = 256
  timeout                        = 25
  reserved_concurrent_executions = var.reserved_concurrency
  filename                       = var.package.path
  source_code_hash               = var.package.base64sha256
  environment {
    variables = {
      ATHENA_WORKGROUP      = local.workgroup
      QUERY_TIMEOUT_SECONDS = "20"
    }
  }
  depends_on = [aws_cloudwatch_log_group.function, aws_iam_role_policy.api]
}

resource "aws_apigatewayv2_api" "findings" {
  name          = local.function_name
  protocol_type = "HTTP"
  description   = "Read-only findings API. Every route requires SigV4-signed IAM credentials."
}

resource "aws_apigatewayv2_integration" "lambda" {
  api_id                 = aws_apigatewayv2_api.findings.id
  integration_type       = "AWS_PROXY"
  integration_uri        = aws_lambda_function.api.invoke_arn
  payload_format_version = "2.0"
  timeout_milliseconds   = 29000
}

resource "aws_apigatewayv2_route" "routes" {
  for_each           = toset(local.routes)
  api_id             = aws_apigatewayv2_api.findings.id
  route_key          = each.value
  authorization_type = "AWS_IAM"
  target             = "integrations/${aws_apigatewayv2_integration.lambda.id}"
}

resource "aws_apigatewayv2_stage" "default" {
  api_id      = aws_apigatewayv2_api.findings.id
  name        = "$default"
  auto_deploy = true
  default_route_settings {
    throttling_burst_limit = 5
    throttling_rate_limit  = 2
  }
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.access.arn
    format = jsonencode({
      requestId = "$context.requestId"
      routeKey  = "$context.routeKey"
      status    = "$context.status"
      caller    = "$context.identity.userArn"
      sourceIp  = "$context.identity.sourceIp"
      latencyMs = "$context.responseLatency"
    })
  }
}

resource "aws_lambda_permission" "api" {
  statement_id  = "AllowFindingsApiRoutes"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.api.function_name
  principal     = "apigateway.amazonaws.com"
  source_arn    = "${aws_apigatewayv2_api.findings.execution_arn}/*/*"
}

output "api_endpoint" { value = aws_apigatewayv2_api.findings.api_endpoint }
output "function_name" { value = aws_lambda_function.api.function_name }

output "invoke_policy" {
  description = "Attach to a dedicated reader identity after review; this module grants no caller access by itself."
  value = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "execute-api:Invoke"
      Resource = [for route in local.routes : "${aws_apigatewayv2_api.findings.execution_arn}/$default/${replace(route, " ", "")}"]
    }]
  })
}
