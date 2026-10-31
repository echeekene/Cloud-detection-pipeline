# GitHub Actions access through OIDC: no AWS keys are stored in GitHub.
# A plan role (read only, no data or secrets) and a deploy role (only the four delivery modules)
# trust tokens from this repository alone. See docs/CICD.md.
terraform {
  required_version = ">= 1.11.0, < 2.0.0"
  # Shared settings come from infra/backend.hcl; see docs/STATE.md.
  backend "s3" {
    key = "cicd/terraform.tfstate"
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

variable "repository" {
  description = "GitHub owner/name allowed to assume the roles. Matching is exact."
  type        = string
  default     = "echeekene/Cloud-detection-pipeline"
  validation {
    condition     = can(regex("^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", var.repository))
    error_message = "Use owner/name with no wildcards."
  }
}

variable "create_oidc_provider" {
  description = "Set true only if the account has no GitHub OIDC provider yet. An account can hold one per URL."
  type        = bool
  default     = false
}

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = [var.expected_account_id]
  default_tags { tags = { Project = "cloud-detection", Purpose = "cicd" } }
}

locals {
  prefix       = "cloud-detection-github"
  issuer       = "token.actions.githubusercontent.com"
  state_bucket = "cloud-detection-${var.expected_account_id}-us-east-1-tfstate"

  # Modules CI may deploy. Foundation, analytics and automation stay manual (see docs/CICD.md).
  modules = ["api", "alerts", "simulator", "monitoring"]

  provider_arn = var.create_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn

  # Pull requests and pushes to main may plan. Only jobs in the protected "production"
  # environment, which needs a manual approval in GitHub, may deploy.
  plan_subjects   = ["repo:${var.repository}:pull_request", "repo:${var.repository}:ref:refs/heads/main"]
  deploy_subjects = ["repo:${var.repository}:environment:production"]
}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_oidc_provider ? 1 : 0
  url            = "https://${local.issuer}"
  client_id_list = ["sts.amazonaws.com"]
}

data "aws_iam_openid_connect_provider" "github" {
  count = var.create_oidc_provider ? 0 : 1
  url   = "https://${local.issuer}"
}

# ---------- Plan role: sees configuration, never data or secrets ----------

resource "aws_iam_role" "plan" {
  name                 = "${local.prefix}-plan"
  description          = "GitHub Actions terraform plan for ${var.repository}."
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = local.provider_arn }
      Condition = { StringEquals = { "${local.issuer}:aud" = "sts.amazonaws.com", "${local.issuer}:sub" = local.plan_subjects } }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "plan_read_only" {
  role       = aws_iam_role.plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# ReadOnlyAccess can read log contents, table items and secrets. Plans need none of that.
resource "aws_iam_role_policy" "plan_no_data" {
  name = "deny-data-and-secrets"
  role = aws_iam_role.plan.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "DenySecrets"
        Effect = "Deny"
        Action = [
          "ssm:GetParameter", "ssm:GetParameters", "ssm:GetParametersByPath", "ssm:GetParameterHistory",
          "secretsmanager:GetSecretValue", "kms:Decrypt",
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyLogAndFindingData"
        Effect = "Deny"
        Action = [
          "dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:GetRecords",
          "athena:GetQueryResults", "athena:GetQueryResultsStream", "logs:GetLogEvents", "logs:FilterLogEvents",
          "logs:StartQuery", "logs:GetQueryResults", "cloudtrail:LookupEvents", "sqs:ReceiveMessage",
        ]
        Resource = "*"
      },
      {
        Sid         = "DenyObjectsExceptState"
        Effect      = "Deny"
        Action      = ["s3:GetObject", "s3:GetObjectVersion"]
        NotResource = ["arn:aws:s3:::${local.state_bucket}/*"]
      },
    ]
  })
}

# ---------- Deploy role: the same scoped policies used for manual deploys ----------

resource "aws_iam_role" "deploy" {
  name                 = "${local.prefix}-deploy"
  description          = "GitHub Actions terraform apply for ${var.repository}, production environment only."
  max_session_duration = 3600
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = local.provider_arn }
      Condition = { StringEquals = { "${local.issuer}:aud" = "sts.amazonaws.com", "${local.issuer}:sub" = local.deploy_subjects } }
    }]
  })
}

resource "aws_iam_policy" "deploy" {
  for_each    = toset(local.modules)
  name        = "${local.prefix}-deploy-${each.key}"
  description = "CI deploy permissions for infra/${each.key}, rendered from infra/access/${each.key}-policy.json.tftpl."
  policy      = templatefile("${path.module}/../access/${each.key}-policy.json.tftpl", { account_id = var.expected_account_id })
}

resource "aws_iam_role_policy_attachment" "deploy" {
  for_each   = aws_iam_policy.deploy
  role       = aws_iam_role.deploy.name
  policy_arn = each.value.arn
}

resource "aws_iam_role_policy" "deploy_state" {
  name = "terraform-state"
  role = aws_iam_role.deploy.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ListStateKeys"
        Effect   = "Allow"
        Action   = "s3:ListBucket"
        Resource = "arn:aws:s3:::${local.state_bucket}"
      },
      {
        Sid      = "ReadWriteDeliveryState"
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"]
        Resource = flatten([for m in local.modules : ["arn:aws:s3:::${local.state_bucket}/${m}/terraform.tfstate", "arn:aws:s3:::${local.state_bucket}/${m}/terraform.tfstate.tflock"]])
      },
    ]
  })
}

output "plan_role_arn" { value = aws_iam_role.plan.arn }
output "deploy_role_arn" { value = aws_iam_role.deploy.arn }
output "deploy_policy_names" { value = sort([for p in aws_iam_policy.deploy : p.name]) }
