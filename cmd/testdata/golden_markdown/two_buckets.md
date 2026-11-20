# Remediation summary

> Nothing was applied. These are proposals; apply them, then re-scan to confirm the findings are fixed.

## `prowler/s3_bucket_level_public_access_block` — S3 bucket without Block Public Access

- `terraform/s3_public_access_block__bucket-one.tf` — `bucket-one`, `eu-central-1` — `code generated`
- `terraform/s3_public_access_block__bucket-two.tf` — `arn:aws:s3:::bucket-two`, `eu-central-1` — `code generated`
- `evil????resource??aws_iam_user???x???`, `eu-central-1` — `skipped`

## `prowler/s3_bucket_public_access` — S3 bucket publicly accessible

- `terraform/s3_public_access_block__bucket-two.tf` — `bucket-two`, `eu-central-1` — `code generated`

## `prowler/eks_cluster_not_publicly_accessible` — EKS API server endpoint open to the internet

- `prod`, `eu-central-1` — `guidance only`

## `prowler/iam_root_hardware_mfa_enabled` — Ensure hardware MFA is enabled for the root account \| urgent

- `?root_account?`, `us-east-1` — `no mapping`
