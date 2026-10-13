# Remediation mapping

> **Technical Remediation & Evidence Assistant for NIS2/DORA.** This tool does not certify compliance; risk acceptance remains with the client's management.

| Scanner | Check | Resource | Articles | Generated | Status | Note |
|---|---|---|---|---|---|---|
| prowler | s3_bucket_level_public_access_block | acme-customer-exports | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__acme-customer-exports.tf | remediated |  |
| prowler | s3_bucket_level_public_access_block | acme-public-logs | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__acme-public-logs.tf | remediated |  |
| prowler | s3_bucket_public_access | acme-public-logs | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__acme-public-logs.tf | remediated |  |
| prowler | s3_bucket_public_list_acl | acme-public-logs | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__acme-public-logs.tf | remediated |  |
| prowler | s3_bucket_policy_public_write_access | acme-pubpolicy | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__acme-pubpolicy.tf | remediated |  |
| prowler | s3_bucket_kms_encryption | acme-backup-dump | NIS2 Art.21(2)(h), DORA Art.9, ISO27001:2022 A.8.24 | terraform/s3_encryption_kms__acme-backup-dump.tf, terraform/variables_kms_key.tf | remediated |  |
| prowler | ec2_securitygroup_allow_ingress_from_internet_to_all_ports | sg-1534e2968c20202a0 | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | terraform/sg_restrict_ingress__sg-1534e2968c20202a0.tf, terraform/variables_sg_ingress.tf | remediated |  |
| prowler | ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22 | sg-a899c3f6063affe1f | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | terraform/sg_restrict_ingress__sg-a899c3f6063affe1f.tf, terraform/variables_sg_ingress.tf | remediated |  |
| prowler | eks_cluster_not_publicly_accessible | acme-eks | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 |  | guidance only | Change the existing aws_eks_cluster vpc_config: set endpoint_public_access = false and endpoint_private_access = true, or limit public_access_cidrs to admin ranges. Confirm private connectivity (VPN, Direct Connect or bastion) first, or kubectl access is lost. |
| prowler | ec2_ebs_default_encryption | 000000000000 | NIS2 Art.21(2)(h), DORA Art.9, ISO27001:2022 A.8.24 | terraform/ebs_default_encryption__000000000000_us-east-1.tf | remediated |  |
| prowler | s3_bucket_acl_prohibited | acme-backup-dump | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.5.15, ISO27001:2022 A.8.3 | terraform/s3_acl_prohibited__acme-backup-dump.tf | remediated |  |
