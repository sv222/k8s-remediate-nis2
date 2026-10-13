# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# Set var.access_log_bucket (see variables_access_log.tf). The log bucket must exist in the same
# region, must allow log delivery from S3, and must not use SSE-KMS default encryption.
# Do not use {{ .ResourceID }} as its own log bucket unless you accept log growth and extra cost.
resource "aws_s3_bucket_logging" "access_logs_{{ .SanitizedResourceID }}" {
  bucket        = "{{ .ResourceID }}"
  target_bucket = var.access_log_bucket
  target_prefix = "{{ .ResourceID }}/"
}
