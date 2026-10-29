mock_provider "aws" {
  mock_resource "aws_iam_role" {
    defaults = { arn = "arn:aws:iam::111122223333:role/cloud-detection-findings-reader" }
  }
  mock_resource "aws_cloudwatch_log_group" {
    defaults = { arn = "arn:aws:logs:us-east-1:111122223333:log-group:/aws/apigateway/cloud-detection-findings-api" }
  }
  mock_resource "aws_lambda_function" {
    defaults = {
      arn        = "arn:aws:lambda:us-east-1:111122223333:function:cloud-detection-findings-api"
      invoke_arn = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:111122223333:function:cloud-detection-findings-api/invocations"
    }
  }
  mock_resource "aws_apigatewayv2_api" {
    defaults = {
      id            = "abc123"
      execution_arn = "arn:aws:execute-api:us-east-1:111122223333:abc123"
      api_endpoint  = "https://abc123.execute-api.us-east-1.amazonaws.com"
    }
  }
}

variables {
  expected_account_id = "111122223333"
  package = {
    path         = "mock-api-package.zip"
    sha256       = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    base64sha256 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  }
}

run "every_route_requires_iam_auth" {
  command = apply
  assert {
    condition     = length(aws_apigatewayv2_route.routes) == 3 && alltrue([for route in aws_apigatewayv2_route.routes : route.authorization_type == "AWS_IAM"])
    error_message = "No route may be reachable without signed IAM credentials."
  }
  assert {
    condition     = aws_apigatewayv2_stage.default.default_route_settings[0].throttling_rate_limit == 2 && aws_apigatewayv2_stage.default.default_route_settings[0].throttling_burst_limit == 5
    error_message = "Keep request throttling low to bound cost and abuse."
  }
}

run "read_only_runtime" {
  command = apply
  assert {
    condition = (
      !strcontains(aws_iam_role_policy.api.policy, "glue:Create") &&
      !strcontains(aws_iam_role_policy.api.policy, "glue:Update") &&
      !strcontains(aws_iam_role_policy.api.policy, "glue:Delete") &&
      !strcontains(aws_iam_role_policy.api.policy, "s3:DeleteObject") &&
      jsondecode(aws_iam_role_policy.api.policy).Statement[3].Resource == "arn:aws:s3:::cloud-detection-111122223333-us-east-1-analytics/athena-results/*"
    )
    error_message = "The API may only read tables and write its own query results."
  }
  assert {
    condition     = jsondecode(aws_iam_role_policy.api.policy).Statement[0].Resource == "arn:aws:athena:us-east-1:111122223333:workgroup/cloud-detection-queries"
    error_message = "Queries must run in the scan-limited project workgroup."
  }
  assert {
    condition     = aws_lambda_function.api.timeout == 25 && aws_apigatewayv2_integration.lambda.timeout_milliseconds == 29000 && aws_cloudwatch_log_group.function.retention_in_days == 3 && aws_cloudwatch_log_group.access.retention_in_days == 3
    error_message = "Bound runtime and keep logs short-lived."
  }
}

run "invoke_policy_is_route_scoped" {
  command = apply
  assert {
    condition     = contains(jsondecode(output.invoke_policy).Statement[0].Resource, "arn:aws:execute-api:us-east-1:111122223333:abc123/$default/GET/findings") && length(jsondecode(output.invoke_policy).Statement[0].Resource) == 3
    error_message = "Callers should be granted only the three read routes."
  }
}
