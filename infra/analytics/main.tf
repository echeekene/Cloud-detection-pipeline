data "aws_partition" "current" {}

locals {
  bucket_name   = "${var.project_name}-${var.expected_account_id}-${var.aws_region}-analytics"
  database_name = replace(var.project_name, "-", "_")
  columns       = jsondecode(file("${path.module}/columns.json"))
  bucket_arn    = "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name}"
  partitions = merge([for table, dataset in var.datasets : {
    for partition in dataset.partitions : "${table}/${partition.event_date}/${partition.region}" => {
      table       = table
      snapshot_id = dataset.snapshot_id
      event_date  = partition.event_date
      region      = partition.region
    }
  }]...)
}

resource "aws_s3_bucket" "analytics" {
  bucket        = local.bucket_name
  force_destroy = var.allow_data_deletion
}

resource "aws_s3_bucket_public_access_block" "analytics" {
  bucket                  = aws_s3_bucket.analytics.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_versioning" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_lifecycle_configuration" "analytics" {
  bucket     = aws_s3_bucket.analytics.id
  depends_on = [aws_s3_bucket_versioning.analytics]
  rule {
    id     = "expire-short-lived-lab-data"
    status = "Enabled"
    filter {}
    expiration { days = 7 }
    noncurrent_version_expiration { noncurrent_days = 7 }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
  rule {
    id     = "remove-expired-delete-markers"
    status = "Enabled"
    filter {}
    expiration { expired_object_delete_marker = true }
  }
}

resource "aws_s3_bucket_policy" "analytics" {
  bucket = aws_s3_bucket.analytics.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })
  depends_on = [aws_s3_bucket_public_access_block.analytics]
}

resource "aws_athena_workgroup" "queries" {
  name          = "${var.project_name}-queries"
  description   = "Small manual SQL checks for our student security project."
  force_destroy = false
  configuration {
    enforce_workgroup_configuration    = true
    bytes_scanned_cutoff_per_query     = 10485760
    publish_cloudwatch_metrics_enabled = false
    engine_version { selected_engine_version = "Athena engine version 3" }
    result_configuration {
      output_location       = "s3://${aws_s3_bucket.analytics.id}/athena-results/"
      expected_bucket_owner = var.expected_account_id
      encryption_configuration { encryption_option = "SSE_S3" }
    }
  }
  depends_on = [
    aws_s3_bucket_policy.analytics,
    aws_s3_bucket_server_side_encryption_configuration.analytics,
    aws_s3_bucket_ownership_controls.analytics,
    aws_s3_bucket_lifecycle_configuration.analytics
  ]
}

resource "aws_glue_catalog_database" "project" {
  catalog_id  = var.expected_account_id
  name        = local.database_name
  description = "Tables for learning SQL on our security logs."
}

resource "aws_glue_catalog_table" "events" {
  for_each      = var.datasets
  catalog_id    = var.expected_account_id
  database_name = aws_glue_catalog_database.project.name
  name          = each.key
  table_type    = "EXTERNAL_TABLE"
  parameters = {
    EXTERNAL       = "TRUE"
    classification = "parquet"
    sample_kind    = each.key == "synthetic_events" ? "synthetic" : "live"
  }
  partition_keys {
    name = "event_date"
    type = "string"
  }
  partition_keys {
    name = "region"
    type = "string"
  }
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.analytics.id}/datasets/${each.key}/${each.value.snapshot_id}/parquet/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }
    dynamic "columns" {
      for_each = local.columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}

resource "aws_glue_partition" "events" {
  for_each         = local.partitions
  catalog_id       = var.expected_account_id
  database_name    = aws_glue_catalog_database.project.name
  table_name       = aws_glue_catalog_table.events[each.value.table].name
  partition_values = [each.value.event_date, each.value.region]
  storage_descriptor {
    location      = "s3://${aws_s3_bucket.analytics.id}/datasets/${each.value.table}/${each.value.snapshot_id}/parquet/event_date=${each.value.event_date}/region=${each.value.region}/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }
    dynamic "columns" {
      for_each = local.columns
      content {
        name = columns.value.name
        type = columns.value.type
      }
    }
  }
}

# Terraform uploads these small, manually selected files. We can learn the query
# path without adding a processing service or a scheduler yet.
resource "aws_s3_object" "samples" {
  for_each               = var.snapshot_files
  bucket                 = aws_s3_bucket.analytics.id
  key                    = "datasets/${each.value.dataset}/${var.datasets[each.value.dataset].snapshot_id}/${each.value.relative_path}"
  source                 = each.value.source_path
  source_hash            = each.value.sha256
  server_side_encryption = "AES256"
  content_type           = "application/octet-stream"
  lifecycle {
    precondition {
      condition     = filesha256(each.value.source_path) == each.value.sha256
      error_message = "The selected local Parquet file changed. Recheck the snapshot before uploading it."
    }
  }
  depends_on = [
    aws_s3_bucket_policy.analytics,
    aws_s3_bucket_server_side_encryption_configuration.analytics,
    aws_s3_bucket_ownership_controls.analytics,
    aws_s3_bucket_lifecycle_configuration.analytics
  ]
}
