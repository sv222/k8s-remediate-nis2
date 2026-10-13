variable "kms_key_arn" {
  type        = string
  description = "ARN of the customer-managed KMS key used for S3 default encryption"

  validation {
    condition     = can(regex("^arn:aws[a-z-]*:kms:", var.kms_key_arn))
    error_message = "kms_key_arn must be a KMS key ARN."
  }
}
