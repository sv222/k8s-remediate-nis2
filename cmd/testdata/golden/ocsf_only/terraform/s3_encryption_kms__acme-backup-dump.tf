# Remediation for: S3 bucket without SSE-KMS default encryption
# Articles: NIS2 Art.21(2)(h), DORA Art.9, ISO27001:2022 A.8.24
# Set var.kms_key_arn (see variables_kms_key.tf). Do not apply together with the AES256 encryption snippet for the same bucket.
resource "aws_s3_bucket_server_side_encryption_configuration" "remediation_kms_acme-backup-dump" {
  bucket = "acme-backup-dump"

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}
