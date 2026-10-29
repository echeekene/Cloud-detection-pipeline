variable "expected_account_id" {
  description = "Required target account. The AWS provider refuses a different account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Supply the 12-digit AWS account ID chosen for this lab."
  }
}

variable "aws_region" {
  description = "Home region for the trail and log bucket. Choose before deployment."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short lowercase project identifier used in names and tags."
  type        = string
  default     = "cloud-detection"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,23}$", var.project_name))
    error_message = "Use 3-24 lowercase letters, digits, or hyphens, starting with a letter."
  }
}

variable "log_retention_days" {
  description = "Lab evidence retention. Current and noncurrent versions expire after this period."
  type        = number
  default     = 30
  validation {
    condition     = var.log_retention_days >= 7 && var.log_retention_days <= 365 && floor(var.log_retention_days) == var.log_retention_days
    error_message = "Choose a whole number between 7 and 365 days."
  }
}

variable "allow_log_deletion" {
  description = "Explicit teardown opt-in: allow Terraform to empty this lab bucket during destroy. Apply this change before destroy."
  type        = bool
  default     = false
}
