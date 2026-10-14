# Remediation for: S3 bucket without SSE-KMS default encryption
# Articles: NIS2 Art.21(2)(h), DORA Art.9, DORA RTS 2024/1774 Art.6, NIS2 CIR 2024/2690 Annex 9.1, ISO27001:2022 A.8.24
# WARNING: S3 server access logs and ELB or CloudFront logs cannot be delivered to a bucket with SSE-KMS default
# encryption. If acme-backup-dump receives logs, do not apply this file: list the bucket in var.kms_excluded_buckets.
# WARNING: every reader of the bucket needs kms:Decrypt on the key, and every writer needs kms:GenerateDataKey.
# Update the key policy and IAM policies first, or reads and writes fail with AccessDenied.
# KMS keys are regional. This bucket is in us-east-1: set var.kms_key_arns["us-east-1"] (see variables_kms_key.tf).
# Existing objects are not re-encrypted. Do not combine this file with an AES256 snippet for the same bucket.
resource "aws_s3_bucket_server_side_encryption_configuration" "remediation_kms_acme-backup-dump" {
  count  = contains(var.kms_excluded_buckets, "acme-backup-dump") ? 0 : 1
  region = "us-east-1"
  bucket = "acme-backup-dump"

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arns["us-east-1"]
    }
  }
}
