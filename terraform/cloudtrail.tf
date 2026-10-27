# CloudTrail records every AWS API call: who did what, from where, and when.
# This is the primary data source for the detections.

resource "aws_cloudtrail" "main" {
  name           = "${var.project_name}-trail"
  s3_bucket_name = aws_s3_bucket.logs.id

  # Attackers often operate in regions the defender is not watching.
  is_multi_region_trail = true

  # Captures global services such as IAM and STS, where most credential abuse shows up.
  include_global_service_events = true

  # Digest files let you prove later that no log was altered or deleted.
  enable_log_file_validation = true

  # First copy of management events in an account is free.
  event_selector {
    read_write_type           = "All"
    include_management_events = true
  }

  depends_on = [aws_s3_bucket_policy.logs]
}
