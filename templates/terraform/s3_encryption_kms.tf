# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# Set var.kms_key_arn (see variables_kms_key.tf). Do not apply together with the AES256 encryption snippet for the same bucket.
resource "aws_s3_bucket_server_side_encryption_configuration" "remediation_kms_{{ .SanitizedResourceID }}" {
  bucket = "{{ .ResourceID }}"

  rule {
    bucket_key_enabled = true

    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
  }
}
