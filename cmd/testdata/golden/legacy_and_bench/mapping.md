# Remediation mapping

> **Technical Remediation & Evidence Assistant for NIS2/DORA.** This tool does not certify compliance; risk acceptance remains with the client's management.

> **Nothing was applied.** Generated files are proposals. Status `code generated` or `follow-up required` does not mean the finding is fixed. See the Note column for what stays open.

| Scanner | Check | Resource | Articles | Generated | Status | Note |
|---|---|---|---|---|---|---|
| `prowler` | `s3_bucket_level_public_access_block` | `acme-customer-exports` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.21, NIS2 CIR 2024/2690 Annex 11.1, ISO27001:2022 A.8.3 | `terraform/s3_public_access_block__acme-customer-exports.tf` | code generated | Not applied. Apply it, then re-scan to confirm. |
| `prowler` | `s3_bucket_level_public_access_block` | `acme-public-logs` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.21, NIS2 CIR 2024/2690 Annex 11.1, ISO27001:2022 A.8.3 | `terraform/s3_public_access_block__acme-public-logs.tf` | code generated | Not applied. Apply it, then re-scan to confirm. |
| `prowler` | `s3_bucket_public_access` | `acme-public-logs` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.21, NIS2 CIR 2024/2690 Annex 11.1, ISO27001:2022 A.8.3 | `terraform/s3_public_access_block__acme-public-logs.tf` | code generated | Not applied. Apply it, then re-scan to confirm. |
| `prowler` | `s3_bucket_kms_encryption` | `acme-backup-dump` | NIS2 Art.21(2)(h), DORA Art.9, DORA RTS 2024/1774 Art.6, NIS2 CIR 2024/2690 Annex 9.1, ISO27001:2022 A.8.24 | `terraform/s3_encryption_kms__acme-backup-dump.tf`, `terraform/variables_kms_key.tf` | follow-up required | Not applied. Default encryption applies to new objects only. Existing objects are not re-encrypted. Set kms_key_arns for the bucket region, and exclude log target buckets in kms_excluded_buckets. Caution: SSE-KMS breaks S3 and ELB log delivery to this bucket. Readers need kms:Decrypt. KMS keys are regional. |
| `prowler` | `ec2_securitygroup_allow_ingress_from_internet_to_any_port` | `sg-a899c3f6063affe1f` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.13, NIS2 CIR 2024/2690 Annex 6.7, ISO27001:2022 A.8.20 |  | guidance only | No code is generated on purpose. The finding does not say which port the workload needs, and a guessed port could add access that was never there. Find the open rule: aws ec2 describe-security-groups --group-ids SG. Add a rule for the needed port and your trusted CIDR: aws ec2 authorize-security-group-ingress --group-id SG --protocol tcp --port PORT --cidr TRUSTED_CIDR. Then remove the open rule: aws ec2 revoke-security-group-ingress --group-id SG --ip-permissions IpProtocol=PROTO,FromPort=N,ToPort=N,IpRanges=\[{CidrIp=0.0.0.0/0}\]. Open rules to many ports usually need a review of what the workload really uses. |
| `prowler` | `ec2_ebs_default_encryption` | `000000000000` | NIS2 Art.21(2)(h), DORA Art.9, DORA RTS 2024/1774 Art.6, NIS2 CIR 2024/2690 Annex 9.1, ISO27001:2022 A.8.24 | `terraform/ebs_default_encryption__000000000000_us-east-1.tf` | follow-up required | Not applied. Applies to new volumes and snapshot copies in this region only. Existing unencrypted volumes stay unencrypted: snapshot, copy with encryption and replace them. |
| `kube-bench` | `1.1.12` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `1.2.5` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `1.2.15` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `1.2.16` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `1.2.17` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `1.2.18` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `1.2.19` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `1.2.30` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `1.3.2` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `1.4.1` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `4.1.1` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `4.1.9` | `cluster` |  |  | no mapping |  |
| `kube-bench` | `5.2.2` | `cluster` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.11, NIS2 CIR 2024/2690 Annex 6.3, ISO27001:2022 A.8.9 | `kyverno/block_privileged.yaml` | follow-up required | kube-bench reports this control as manual (WARN). Not applied. The policy starts in Audit mode and blocks nothing. It is not applied to any cluster and existing pods are not changed. Review the policy reports, then set validationActions to Deny to block privileged containers. |
| `kube-bench` | `5.2.5` | `cluster` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.13, NIS2 CIR 2024/2690 Annex 6.8, ISO27001:2022 A.8.22 | `kyverno/block_hostnet.yaml` | follow-up required | kube-bench reports this control as manual (WARN). Not applied. The policy starts in Audit mode and blocks nothing. It is not applied to any cluster and existing pods are not changed. Review the policy reports, then set validationActions to Deny to block host network pods. |
| `kube-bench` | `5.2.7` | `cluster` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.11, NIS2 CIR 2024/2690 Annex 6.3, ISO27001:2022 A.8.9 | `kyverno/require_nonroot.yaml` | follow-up required | kube-bench reports this control as manual (WARN). Not applied. The policy starts in Audit mode and blocks nothing. It is not applied to any cluster and existing pods are not changed. Review the policy reports, then set validationActions to Deny to block root containers. |
