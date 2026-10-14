# Remediation for: S3 bucket without Block Public Access
# Articles: NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.21, NIS2 CIR 2024/2690 Annex 11.1, ISO27001:2022 A.8.3
# WARNING: Block Public Access removes all public access to bucket-one. Buckets that are public on purpose
# (static websites, public downloads) and CloudFront distributions that read the bucket without Origin Access Control
# stop serving content to the public. Check who reads the bucket first: aws s3api get-bucket-policy-status --bucket bucket-one
resource "aws_s3_bucket_public_access_block" "remediation_bucket-one" {
  bucket = "bucket-one"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
