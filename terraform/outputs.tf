output "account_id" {
  description = "Confirms you deployed into the sandbox account, not the portfolio account."
  value       = local.account_id
}

output "log_bucket" {
  value = aws_s3_bucket.logs.bucket
}

output "athena_workgroup" {
  value = aws_athena_workgroup.detections.name
}

output "glue_database" {
  value = aws_glue_catalog_database.security_logs.name
}

output "cloudtrail_arn" {
  value = aws_cloudtrail.main.arn
}

output "guardduty_detector_id" {
  value = aws_guardduty_detector.main.id
}

output "vpc_id" {
  value = aws_vpc.lab.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}
