# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# WARNING: This applies to EVERY bucket of account {{ .ResourceID }}, present and future. Buckets that are public
# on purpose (static websites, public downloads) stop serving public content and need their own bucket public
# access block to opt out. Check the current settings first:
# aws s3control get-public-access-block --account-id {{ .ResourceID }}
resource "aws_s3_account_public_access_block" "remediation_{{ .SanitizedResourceID }}" {
  account_id = "{{ .ResourceID }}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
