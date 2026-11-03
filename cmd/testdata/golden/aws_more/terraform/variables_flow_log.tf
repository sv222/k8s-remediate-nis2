variable "flow_log_bucket_arn" {
  type        = string
  description = "ARN of the existing S3 bucket that receives VPC flow logs, for example arn:aws:s3:::my-flow-logs. An optional /prefix is allowed"

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](/.*)?$", var.flow_log_bucket_arn))
    error_message = "flow_log_bucket_arn must be the ARN of an S3 bucket."
  }
}
