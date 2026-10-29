output "raw_bucket_name" {
  description = "Dedicated lab log bucket."
  value       = aws_s3_bucket.raw.id
}

output "trail_arn" {
  description = "Trail ARN to use for delivery verification."
  value       = aws_cloudtrail.audit.arn
}

output "cloudtrail_log_prefix" {
  description = "Expected prefix for delivered logs and digests."
  value       = "s3://${local.bucket_name}/${local.log_prefix}/AWSLogs/${var.expected_account_id}/"
}
