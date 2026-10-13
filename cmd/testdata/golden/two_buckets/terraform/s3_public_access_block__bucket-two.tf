# Remediation for: S3 bucket without Block Public Access
# Articles: NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3
resource "aws_s3_bucket_public_access_block" "remediation_bucket-two" {
  bucket = "bucket-two"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
