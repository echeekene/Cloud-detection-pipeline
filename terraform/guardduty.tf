# GuardDuty is AWS's managed threat detection. It analyzes CloudTrail, VPC
# Flow Logs and DNS logs with AWS's own threat intelligence.
#
# Why run it alongside custom SQL detections: it lets the project compare
# managed detection against detections written by hand, and show which
# attacks each one catches or misses. 30 day free trial covers the lab.

resource "aws_guardduty_detector" "main" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}
