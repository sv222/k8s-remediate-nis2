variable "kms_key_arns" {
  type        = map(string)
  description = "ARN of the customer-managed KMS key per AWS region, for example { \"eu-west-1\" = \"arn:aws:kms:eu-west-1:111122223333:key/...\" }. KMS keys are regional: a bucket needs a key of its own region"

  validation {
    condition     = alltrue([for region, arn in var.kms_key_arns : can(regex("^arn:aws[a-z-]*:kms:${region}:", arn))])
    error_message = "Every kms_key_arns value must be a KMS key ARN in the region named by its key."
  }
}

variable "kms_excluded_buckets" {
  type        = list(string)
  default     = []
  description = "Buckets that must NOT get SSE-KMS default encryption, for example the target buckets of S3 server access logs, ELB logs or CloudFront logs. Log delivery cannot write to SSE-KMS buckets"
}
