# Remediation for: S3 bucket has ACLs enabled
# Articles: NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.5.15, ISO27001:2022 A.8.3
# WARNING: BucketOwnerEnforced disables all ACLs of nr-plain. Existing ACL grants stop working.
# Services and partners that depend on ACL grants (for example legacy S3 or CloudFront log delivery,
# cross-account writers that use ACLs) lose access. Check with: aws s3api get-bucket-acl --bucket nr-plain
# S3 can refuse the change while the bucket ACL grants access to other principals. Reset the ACL first.
# This does not widen access.
resource "aws_s3_bucket_ownership_controls" "acls_disabled_nr-plain" {
  bucket = "nr-plain"

  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}
