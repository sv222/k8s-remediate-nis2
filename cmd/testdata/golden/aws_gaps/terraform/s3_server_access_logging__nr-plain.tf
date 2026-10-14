# Remediation for: S3 bucket without server access logging
# Articles: NIS2 Art.21(2)(b), DORA Art.10, DORA RTS 2024/1774 Art.12, NIS2 CIR 2024/2690 Annex 3.2, ISO27001:2022 A.8.15, ISO27001:2022 A.8.16
# Set var.access_log_bucket (see variables_access_log.tf). The log bucket must exist in the same
# region, must allow log delivery from S3, and must not use SSE-KMS default encryption.
# Do not use nr-plain as its own log bucket unless you accept log growth and extra cost.
resource "aws_s3_bucket_logging" "access_logs_nr-plain" {
  bucket        = "nr-plain"
  target_bucket = var.access_log_bucket
  target_prefix = "nr-plain/"
}
