variable "access_log_bucket" {
  type        = string
  description = "Name of the existing S3 bucket that receives server access logs"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.access_log_bucket))
    error_message = "access_log_bucket must be a valid S3 bucket name."
  }
}
