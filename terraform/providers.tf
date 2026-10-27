terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.region
  profile = var.aws_profile

  # Every resource gets these tags automatically, which makes cost tracking
  # and teardown verification easy (filter by Project in the console).
  default_tags {
    tags = {
      Project   = var.project_name
      ManagedBy = "terraform"
      Owner     = "ekene-eche"
    }
  }
}

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  # Account ID in bucket names keeps them globally unique without random strings.
  name_prefix = "${var.project_name}-${local.account_id}"
}
