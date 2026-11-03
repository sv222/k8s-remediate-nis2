variable "cloudtrail_bucket" {
  type        = string
  description = "Name of the existing S3 bucket that receives the CloudTrail log files"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.cloudtrail_bucket))
    error_message = "cloudtrail_bucket must be a valid S3 bucket name."
  }
}

variable "cloudtrail_name" {
  type        = string
  default     = "nis2-multi-region"
  description = "Name of the new multi-region trail"
}
