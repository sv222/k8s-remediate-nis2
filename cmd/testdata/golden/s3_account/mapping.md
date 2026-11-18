# Remediation mapping

> **Technical Remediation & Evidence Assistant for NIS2/DORA.** This tool does not certify compliance; risk acceptance remains with the client's management.

> **Nothing was applied.** Generated files are proposals. Status `code generated` or `follow-up required` does not mean the finding is fixed. See the Note column for what stays open.

| Scanner | Check | Resource | Articles | Generated | Status | Note |
|---|---|---|---|---|---|---|
| `prowler` | `s3_account_level_public_access_blocks` | `000000000000` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.21, NIS2 CIR 2024/2690 Annex 11.1, ISO27001:2022 A.8.3 | `terraform/s3_account_public_access_block__000000000000.tf` | code generated | Not applied. Apply it, then re-scan to confirm. Caution: Applies to every bucket of the account, present and future. Buckets that are public on purpose need their own bucket public access block to opt out. |
