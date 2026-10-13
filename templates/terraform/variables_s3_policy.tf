data "aws_partition" "current" {}

variable "s3_existing_bucket_policies" {
  type        = map(string)
  default     = {}
  description = "Current bucket policy JSON per bucket name. It is merged into the generated policy so existing statements are kept. Read it with: aws s3api get-bucket-policy --bucket NAME --query Policy --output text"
}
