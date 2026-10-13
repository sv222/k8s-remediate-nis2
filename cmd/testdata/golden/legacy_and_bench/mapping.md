# Remediation mapping

> **Technical Remediation & Evidence Assistant for NIS2/DORA.** This tool does not certify compliance; risk acceptance remains with the client's management.

| Scanner | Check | Resource | Articles | Generated | Status | Note |
|---|---|---|---|---|---|---|
| prowler | s3_bucket_level_public_access_block | acme-customer-exports | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__acme-customer-exports.tf | remediated |  |
| prowler | s3_bucket_level_public_access_block | acme-public-logs | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__acme-public-logs.tf | remediated |  |
| prowler | s3_bucket_public_access | acme-public-logs | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__acme-public-logs.tf | remediated |  |
| prowler | s3_bucket_kms_encryption | acme-backup-dump | NIS2 Art.21(2)(h), DORA Art.9, ISO27001:2022 A.8.24 | terraform/s3_encryption_kms__acme-backup-dump.tf, terraform/variables_kms_key.tf | remediated |  |
| prowler | ec2_securitygroup_allow_ingress_from_internet_to_any_port | sg-a899c3f6063affe1f | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | terraform/sg_restrict_ingress__sg-a899c3f6063affe1f.tf, terraform/variables_sg_ingress.tf | remediated |  |
| prowler | ec2_ebs_default_encryption | 000000000000 |  |  | no mapping |  |
| kube-bench | 1.1.12 | cluster |  |  | no mapping |  |
| kube-bench | 5.2.2 | cluster | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.2 | kyverno/block_privileged.yaml | remediated | kube-bench reports this control as manual (WARN). |
| kube-bench | 5.2.5 | cluster | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.22 | kyverno/block_hostnet.yaml | remediated | kube-bench reports this control as manual (WARN). |
| kube-bench | 5.2.7 | cluster | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.2 | kyverno/require_nonroot.yaml | remediated | kube-bench reports this control as manual (WARN). |
