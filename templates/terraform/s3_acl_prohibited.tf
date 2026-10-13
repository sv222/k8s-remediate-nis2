# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# WARNING: BucketOwnerEnforced disables all ACLs of {{ .ResourceID }}. Existing ACL grants stop working.
# Services and partners that depend on ACL grants (for example legacy S3 or CloudFront log delivery,
# cross-account writers that use ACLs) lose access. Check with: aws s3api get-bucket-acl --bucket {{ .ResourceID }}
# S3 can refuse the change while the bucket ACL grants access to other principals. Reset the ACL first.
# This does not widen access.
resource "aws_s3_bucket_ownership_controls" "acls_disabled_{{ .SanitizedResourceID }}" {
  bucket = "{{ .ResourceID }}"

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
