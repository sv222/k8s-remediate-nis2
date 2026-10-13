# Remediation for: S3 bucket allows requests over plain HTTP
# Articles: NIS2 Art.21(2)(h), DORA Art.9, ISO27001:2022 A.8.24, ISO27001:2022 A.8.20
# WARNING: this denies every request to the bucket that does not use HTTPS. Clients, scripts and
# tools that use plain HTTP lose access to nr-existing-policy. Check the access logs first.
# WARNING: aws_s3_bucket_policy REPLACES the whole bucket policy. Put the current policy JSON of
# this bucket into var.s3_existing_bucket_policies["nr-existing-policy"] (see variables_s3_policy.tf)
# or the existing statements are removed. Review the plan before you apply.
data "aws_iam_policy_document" "secure_transport_nr-existing-policy" {
  source_policy_documents = compact([lookup(var.s3_existing_bucket_policies, "nr-existing-policy", "")])

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      "arn:${data.aws_partition.current.partition}:s3:::nr-existing-policy",
      "arn:${data.aws_partition.current.partition}:s3:::nr-existing-policy/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "secure_transport_nr-existing-policy" {
  bucket = "nr-existing-policy"
  policy = data.aws_iam_policy_document.secure_transport_nr-existing-policy.json
}
