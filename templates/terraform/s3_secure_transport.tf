# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# WARNING: this denies every request to the bucket that does not use HTTPS. Clients, scripts and
# tools that use plain HTTP lose access to {{ .ResourceID }}. Check the access logs first.
# WARNING: aws_s3_bucket_policy REPLACES the whole bucket policy. Put the current policy JSON of
# this bucket into var.s3_existing_bucket_policies["{{ .ResourceID }}"] (see variables_s3_policy.tf)
# or the existing statements are removed. Review the plan before you apply.
data "aws_iam_policy_document" "secure_transport_{{ .SanitizedResourceID }}" {
  source_policy_documents = compact([lookup(var.s3_existing_bucket_policies, "{{ .ResourceID }}", "")])

  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      "arn:${data.aws_partition.current.partition}:s3:::{{ .ResourceID }}",
      "arn:${data.aws_partition.current.partition}:s3:::{{ .ResourceID }}/*",
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

resource "aws_s3_bucket_policy" "secure_transport_{{ .SanitizedResourceID }}" {
  bucket = "{{ .ResourceID }}"
  policy = data.aws_iam_policy_document.secure_transport_{{ .SanitizedResourceID }}.json
}
