# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# WARNING: Block Public Access removes all public access to {{ .ResourceID }}. Buckets that are public on purpose
# (static websites, public downloads) and CloudFront distributions that read the bucket without Origin Access Control
# stop serving content to the public. Check who reads the bucket first: aws s3api get-bucket-policy-status --bucket {{ .ResourceID }}
resource "aws_s3_bucket_public_access_block" "remediation_{{ .SanitizedResourceID }}" {
  bucket = "{{ .ResourceID }}"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
