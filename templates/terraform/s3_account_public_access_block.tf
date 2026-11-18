# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# The file sets no account_id: aws_s3_account_public_access_block applies to the account of the
# Terraform AWS provider. Check that this is the flagged account {{ .ResourceID }} first:
# aws sts get-caller-identity
# WARNING: This applies to EVERY bucket of that account, present and future. Buckets that are public
# on purpose (static websites, public downloads) stop serving public content and need their own bucket
# public access block to opt out.
resource "aws_s3_account_public_access_block" "remediation_{{ .SanitizedResourceID }}" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
