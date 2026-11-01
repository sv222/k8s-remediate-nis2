# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# WARNING: aws_iam_account_password_policy REPLACES the whole password policy of account {{ .ResourceID }}.
# Settings that are not in this file go back to their defaults. Read the current policy first:
# aws iam get-account-password-policy. Copy max_password_age and hard_expiry here if you use them.
# The new rules apply when a user sets a password. Existing passwords are not checked.
resource "aws_iam_account_password_policy" "strict_{{ .SanitizedResourceID }}" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  allow_users_to_change_password = true
}
