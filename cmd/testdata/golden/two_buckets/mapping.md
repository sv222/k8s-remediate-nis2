# Remediation mapping

| Scanner | Check | Resource | Articles | Generated | Status | Note |
|---|---|---|---|---|---|---|
| prowler | s3_bucket_level_public_access_block | bucket-one | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__bucket-one.tf | remediated |  |
| prowler | s3_bucket_level_public_access_block | arn:aws:s3:::bucket-two | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__bucket-two.tf | remediated |  |
| prowler | s3_bucket_public_access | bucket-two | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__bucket-two.tf | remediated |  |
| prowler | s3_bucket_level_public_access_block | evil" } resource "aws_iam_user" "x" { | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 |  | skipped: invalid resource id | invalid resource id: "evil\\"\\n}\\nresource \\"aws_iam_user\\" \\"x\\" {" contains characters outside [A-Za-z0-9._:/@+=,-] |
| prowler | eks_cluster_not_publicly_accessible | prod | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 |  | guidance only | Change the existing aws_eks_cluster vpc_config: set endpoint_public_access = false and endpoint_private_access = true, or limit public_access_cidrs to admin ranges. Confirm private connectivity (VPN, Direct Connect or bastion) first, or kubectl access is lost. |
| prowler | iam_root_mfa_enabled | &lt;root_account&gt; |  |  | no mapping |  |
