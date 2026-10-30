terraform {
  required_version = ">= 1.11.0, < 2.0.0"
  # Shared settings come from infra/backend.hcl; see docs/STATE.md.
  backend "s3" {
    key = "analytics/terraform.tfstate"
  }
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.expected_account_id]
  default_tags {
    tags = {
      Project   = var.project_name
      ManagedBy = "Terraform"
      Purpose   = "SecurityPortfolioLab"
    }
  }
}
