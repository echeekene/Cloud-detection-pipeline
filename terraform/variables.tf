variable "region" {
  description = "Primary AWS region. us-east-1 has the widest Bedrock model availability."
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile for the SANDBOX account, never the account hosting the portfolio site."
  type        = string
  default     = "detection-sandbox"
}

variable "project_name" {
  description = "Short name used as a prefix for resources."
  type        = string
  default     = "cdp"
}

variable "log_retention_days" {
  description = "Raw logs are deleted after this many days. Short on purpose: this is a temporary lab."
  type        = number
  default     = 30
}

variable "vpc_cidr" {
  description = "Address range for the lab VPC. Splunk will live here."
  type        = string
  default     = "10.20.0.0/16"
}

variable "athena_scan_limit_bytes" {
  description = "Hard cap on data scanned per Athena query, a guardrail against a runaway bill."
  type        = number
  default     = 1073741824 # 1 GB
}
