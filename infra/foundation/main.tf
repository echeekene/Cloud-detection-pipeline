data "aws_partition" "current" {}

locals {
  trail_name  = "${var.project_name}-audit"
  bucket_name = "${var.project_name}-${var.expected_account_id}-${var.aws_region}-raw"
  trail_arn   = "arn:${data.aws_partition.current.partition}:cloudtrail:${var.aws_region}:${var.expected_account_id}:trail/${local.trail_name}"
  bucket_arn  = "arn:${data.aws_partition.current.partition}:s3:::${local.bucket_name}"
  log_prefix  = "cloudtrail"

  # jsonencode keeps policy content testable without mocking a policy-document data source.
  bucket_policy = {
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [local.bucket_arn, "${local.bucket_arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = local.bucket_arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${local.bucket_arn}/${local.log_prefix}/AWSLogs/${var.expected_account_id}/*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = local.trail_arn
            "s3:x-amz-acl"  = "bucket-owner-full-control"
          }
        }
      }
    ]
  }
}

resource "aws_s3_bucket" "raw" {
  bucket        = local.bucket_name
  force_destroy = var.allow_log_deletion
}

resource "aws_s3_bucket_public_access_block" "raw" {
  bucket                  = aws_s3_bucket.raw.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "raw" {
  bucket = aws_s3_bucket.raw.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw" {
  bucket = aws_s3_bucket.raw.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "raw" {
  bucket = aws_s3_bucket.raw.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "raw" {
  bucket     = aws_s3_bucket.raw.id
  depends_on = [aws_s3_bucket_versioning.raw]
  rule {
    id     = "expire-lab-logs"
    status = "Enabled"
    filter { prefix = "${local.log_prefix}/" }
    expiration { days = var.log_retention_days }
    noncurrent_version_expiration { noncurrent_days = var.log_retention_days }
    abort_incomplete_multipart_upload { days_after_initiation = 1 }
  }
  rule {
    id     = "remove-expired-delete-markers"
    status = "Enabled"
    filter { prefix = "${local.log_prefix}/" }
    expiration { expired_object_delete_marker = true }
  }
}

resource "aws_s3_bucket_policy" "raw" {
  bucket     = aws_s3_bucket.raw.id
  policy     = jsonencode(local.bucket_policy)
  depends_on = [aws_s3_bucket_public_access_block.raw]
}

resource "aws_cloudtrail" "audit" {
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.raw.id
  s3_key_prefix                 = local.log_prefix
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  enable_logging                = true

  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [
    aws_s3_bucket_policy.raw,
    aws_s3_bucket_ownership_controls.raw,
    aws_s3_bucket_server_side_encryption_configuration.raw,
    aws_s3_bucket_versioning.raw,
    aws_s3_bucket_lifecycle_configuration.raw
  ]
}
