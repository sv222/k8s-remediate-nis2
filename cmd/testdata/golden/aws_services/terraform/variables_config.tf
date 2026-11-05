variable "config_role_arn" {
  type        = string
  description = "ARN of the existing IAM role AWS Config uses, for example the service-linked role arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:iam::[0-9]{12}:role/.+$", var.config_role_arn))
    error_message = "config_role_arn must be the ARN of an IAM role."
  }
}

variable "config_bucket" {
  type        = string
  description = "Name of the existing S3 bucket that receives the AWS Config snapshots and history"

  validation {
    condition     = can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.config_bucket))
    error_message = "config_bucket must be a valid S3 bucket name."
  }
}
