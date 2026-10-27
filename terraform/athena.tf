# Athena lets you run SQL directly against the logs in S3, with no database
# servers to manage. Detection rules are Athena queries.

resource "aws_athena_workgroup" "detections" {
  name          = "${var.project_name}-detections"
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    # Cost guardrail: any query that would scan more than this is cancelled.
    bytes_scanned_cutoff_per_query = var.athena_scan_limit_bytes

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/results/"
      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }
}

resource "aws_glue_catalog_database" "security_logs" {
  name = "${var.project_name}_security_logs" # Glue names allow underscores, not hyphens
}

# Table definitions live as plain SQL in ../sql/ddl so they are readable on
# GitHub. Terraform fills in the bucket, account and region, then saves them
# as Named Queries. Run each one once in the Athena console after apply.

locals {
  ddl_vars = {
    database = aws_glue_catalog_database.security_logs.name
    bucket   = aws_s3_bucket.logs.bucket
    account  = local.account_id
    region   = var.region
  }
}

resource "aws_athena_named_query" "create_cloudtrail_table" {
  name      = "00_create_cloudtrail_table"
  workgroup = aws_athena_workgroup.detections.name
  database  = aws_glue_catalog_database.security_logs.name
  query     = templatefile("${path.module}/../sql/ddl/cloudtrail_table.sql", local.ddl_vars)
}

resource "aws_athena_named_query" "create_flow_logs_table" {
  name      = "01_create_vpc_flow_logs_table"
  workgroup = aws_athena_workgroup.detections.name
  database  = aws_glue_catalog_database.security_logs.name
  query     = templatefile("${path.module}/../sql/ddl/vpc_flow_logs_table.sql", local.ddl_vars)
}

resource "aws_athena_named_query" "sanity_check" {
  name      = "02_sanity_check_recent_events"
  workgroup = aws_athena_workgroup.detections.name
  database  = aws_glue_catalog_database.security_logs.name
  query     = templatefile("${path.module}/../sql/ddl/sanity_check.sql", local.ddl_vars)
}
