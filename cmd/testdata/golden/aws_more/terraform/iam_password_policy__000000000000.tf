# Remediation for: IAM password policy allows passwords shorter than 14 characters; IAM password policy does not prevent reuse of the last 24 passwords
# Articles: NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.21, NIS2 CIR 2024/2690 Annex 11.6, ISO27001:2022 A.5.17
# WARNING: aws_iam_account_password_policy REPLACES the whole password policy of account 000000000000.
# Settings that are not in this file go back to their defaults. Read the current policy first:
# aws iam get-account-password-policy. Copy max_password_age and hard_expiry here if you use them.
# The new rules apply when a user sets a password. Existing passwords are not checked.
resource "aws_iam_account_password_policy" "strict_000000000000" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  allow_users_to_change_password = true
}
