terraform {
  required_version = ">= 1.11.0, < 2.0.0"
  # Shared settings come from infra/backend.hcl; see docs/STATE.md.
  backend "s3" {
    key = "scenario/terraform.tfstate"
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

provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = { Project = "cloud-detection", Purpose = "controlled-iam-scenario" }
  }
}

resource "aws_iam_user" "test" {
  name          = "cloud-detection-scenario-user"
  path          = "/cloud-detection-lab/"
  force_destroy = false
}

resource "aws_iam_policy" "metadata" {
  name        = "cloud-detection-scenario-bucket-location"
  path        = "/cloud-detection-lab/"
  description = "Temporary scenario permission to read only the project bucket location."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetBucketLocation"]
      Resource = "arn:aws:s3:::cloud-detection-${var.expected_account_id}-us-east-1-raw"
    }]
  })
}

resource "aws_iam_user_policy_attachment" "test" {
  user       = aws_iam_user.test.name
  policy_arn = aws_iam_policy.metadata.arn
}

output "test_user" {
  value = aws_iam_user.test.name
}

output "test_policy_arn" {
  value = aws_iam_policy.metadata.arn
}
