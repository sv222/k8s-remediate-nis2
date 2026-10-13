# Remediation for: {{ .Title }}
# Articles: {{ range .Articles }}{{ . }} {{ end }}
resource "aws_s3_bucket_server_side_encryption_configuration" "remediation_{{ .SanitizedResourceID }}" {
  bucket = "{{ .ResourceID }}"
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}
