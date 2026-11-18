# Remediation for: S3 Block Public Access is not set at the account level
# Articles: NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.21, NIS2 CIR 2024/2690 Annex 11.1, ISO27001:2022 A.8.3
# WARNING: This applies to EVERY bucket of account 000000000000, present and future. Buckets that are public
# on purpose (static websites, public downloads) stop serving public content and need their own bucket public
# access block to opt out. Check the current settings first:
# aws s3control get-public-access-block --account-id 000000000000
resource "aws_s3_account_public_access_block" "remediation_000000000000" {
  account_id = "000000000000"

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
