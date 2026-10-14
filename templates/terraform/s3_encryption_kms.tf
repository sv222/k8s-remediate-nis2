# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# WARNING: S3 server access logs and ELB or CloudFront logs cannot be delivered to a bucket with SSE-KMS default
# encryption. If {{ .ResourceID }} receives logs, do not apply this file: list the bucket in var.kms_excluded_buckets.
# WARNING: every reader of the bucket needs kms:Decrypt on the key, and every writer needs kms:GenerateDataKey.
# Update the key policy and IAM policies first, or reads and writes fail with AccessDenied.
# KMS keys are regional. This bucket is in {{ .Region }}: set var.kms_key_arns["{{ .Region }}"] (see variables_kms_key.tf).
# Existing objects are not re-encrypted. Do not combine this file with an AES256 snippet for the same bucket.
resource "aws_s3_bucket_server_side_encryption_configuration" "remediation_kms_{{ .SanitizedResourceID }}" {
  count  = contains(var.kms_excluded_buckets, "{{ .ResourceID }}") ? 0 : 1
  region = "{{ .Region }}"
  bucket = "{{ .ResourceID }}"

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arns["{{ .Region }}"]
    }
  }
}
