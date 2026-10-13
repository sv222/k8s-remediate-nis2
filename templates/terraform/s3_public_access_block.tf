# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
resource "aws_s3_bucket_public_access_block" "remediation_{{ .SanitizedResourceID }}" {
  bucket = "{{ .ResourceID }}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
