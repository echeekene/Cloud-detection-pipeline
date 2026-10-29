variable "expected_account_id" {
  description = "Account chosen for our lab. The provider rejects a different account."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.expected_account_id))
    error_message = "Supply a 12-digit account ID."
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}

variable "project_name" {
  type    = string
  default = "cloud-detection"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,23}$", var.project_name))
    error_message = "Use 3-24 lowercase letters, digits, or hyphens, starting with a letter."
  }
}

variable "datasets" {
  description = "One real and one synthetic snapshot, with their known partitions. Never combine their input paths."
  type = map(object({
    snapshot_id = string
    partitions  = list(object({ event_date = string, region = string }))
  }))
  validation {
    condition     = toset(keys(var.datasets)) == toset(["security_events", "synthetic_events"])
    error_message = "Provide separate security_events and synthetic_events snapshots."
  }
  validation {
    condition = alltrue([for dataset in values(var.datasets) :
      can(regex("^[a-f0-9]{64}$", dataset.snapshot_id)) && length(dataset.partitions) > 0 &&
      length(dataset.partitions) == length(distinct(dataset.partitions)) &&
      alltrue([for partition in dataset.partitions :
        can(formatdate("YYYY-MM-DD", "${partition.event_date}T00:00:00Z")) &&
        length(partition.region) <= 32 && can(regex("^[a-z]{2}(-[a-z0-9]+)+-[0-9]+$", partition.region))
      ])
    ])
    error_message = "Snapshots need a SHA256 ID and unique valid UTC-day/region partitions."
  }
}

variable "allow_data_deletion" {
  description = "Apply true before teardown to let Terraform empty this lab bucket."
  type        = bool
  default     = false
}

variable "snapshot_files" {
  description = "Small Parquet samples to upload with Terraform after checking their local hashes."
  type = map(object({
    dataset       = string
    relative_path = string
    source_path   = string
    sha256        = string
  }))
  default = {}
  validation {
    condition = alltrue([for item in values(var.snapshot_files) :
      contains(keys(var.datasets), item.dataset) &&
      can(regex("^parquet/event_date=[0-9]{4}-[0-9]{2}-[0-9]{2}/region=[a-z0-9-]+/[a-zA-Z0-9_.-]+[.]parquet$", item.relative_path)) &&
      can(regex("^[a-f0-9]{64}$", item.sha256))
    ])
    error_message = "Uploads must be named Parquet partitions belonging to our selected datasets, with a SHA256 hash."
  }
}
