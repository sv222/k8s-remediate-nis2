# Remediation summary

> Nothing was applied. These are proposals; apply them, then re-scan to confirm the findings are fixed.

## `prowler/s3_bucket_level_public_access_block` — S3 bucket without Block Public Access

- `terraform/s3_public_access_block__acme-customer-exports.tf` — `acme-customer-exports`, `us-east-1`, account `000000000000` — `code generated`
- `terraform/s3_public_access_block__acme-public-logs.tf` — `acme-public-logs`, `us-east-1`, account `000000000000` — `code generated`

## `prowler/s3_bucket_public_access` — S3 bucket publicly accessible

- `terraform/s3_public_access_block__acme-public-logs.tf` — `acme-public-logs`, `us-east-1`, account `000000000000` — `code generated`

## `prowler/s3_bucket_public_list_acl` — S3 bucket publicly listable through ACL

- `terraform/s3_public_access_block__acme-public-logs.tf` — `acme-public-logs`, `us-east-1`, account `000000000000` — `code generated`

## `prowler/s3_bucket_policy_public_write_access` — S3 bucket policy allows public write access

- `terraform/s3_public_access_block__acme-pubpolicy.tf` — `acme-pubpolicy`, `us-east-1`, account `000000000000` — `code generated`

## `prowler/s3_bucket_kms_encryption` — S3 bucket without SSE-KMS default encryption

- `terraform/s3_encryption_kms__acme-backup-dump.tf` — `acme-backup-dump`, `us-east-1`, account `000000000000` — `follow-up required`
- `terraform/variables_kms_key.tf` — `acme-backup-dump`, `us-east-1`, account `000000000000` — `follow-up required`

## `prowler/ec2_securitygroup_allow_ingress_from_internet_to_all_ports` — Security group open to the internet on all ports

- `sg-1534e2968c20202a0`, `us-east-1`, account `000000000000` — `guidance only`

## `prowler/ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` — Security group open to the internet on SSH (port 22)

- `terraform/sg_restrict_ssh__sg-a899c3f6063affe1f.tf` — `sg-a899c3f6063affe1f`, `us-east-1`, account `000000000000` — `follow-up required`
- `terraform/variables_sg_ssh.tf` — `sg-a899c3f6063affe1f`, `us-east-1`, account `000000000000` — `follow-up required`

## `prowler/eks_cluster_not_publicly_accessible` — EKS API server endpoint open to the internet

- `acme-eks`, `us-east-1`, account `000000000000` — `guidance only`

## `prowler/ec2_ebs_default_encryption` — EBS default encryption is not enabled

- `terraform/ebs_default_encryption__000000000000_us-east-1.tf` — `000000000000`, `us-east-1`, account `000000000000` — `follow-up required`

## `prowler/s3_bucket_acl_prohibited` — S3 bucket has ACLs enabled

- `terraform/s3_acl_prohibited__acme-backup-dump.tf` — `acme-backup-dump`, `us-east-1`, account `000000000000` — `code generated`

## `kube-bench/1.1.12` — Ensure that the etcd data directory ownership is set to etcd:etcd (Automated)

- `cluster` — `no mapping`

## `kube-bench/1.2.5` — Ensure that the --kubelet-certificate-authority argument is set as appropriate (Automated)

- `cluster` — `no mapping`

## `kube-bench/1.2.15` — Ensure that the --profiling argument is set to false (Automated)

- `cluster` — `no mapping`

## `kube-bench/1.2.16` — Ensure that the --audit-log-path argument is set (Automated)

- `cluster` — `no mapping`

## `kube-bench/1.2.17` — Ensure that the --audit-log-maxage argument is set to 30 or as appropriate (Automated)

- `cluster` — `no mapping`

## `kube-bench/1.2.18` — Ensure that the --audit-log-maxbackup argument is set to 10 or as appropriate (Automated)

- `cluster` — `no mapping`

## `kube-bench/1.2.19` — Ensure that the --audit-log-maxsize argument is set to 100 or as appropriate (Automated)

- `cluster` — `no mapping`

## `kube-bench/1.2.30` — Ensure that the --service-account-extend-token-expiration parameter is set to false (Automated)

- `cluster` — `no mapping`

## `kube-bench/1.3.2` — Ensure that the --profiling argument is set to false (Automated)

- `cluster` — `no mapping`

## `kube-bench/1.4.1` — Ensure that the --profiling argument is set to false (Automated)

- `cluster` — `no mapping`

## `kube-bench/4.1.1` — Ensure that the kubelet service file permissions are set to 600 or more restrictive (Automated)

- `cluster` — `no mapping`

## `kube-bench/4.1.9` — If the kubelet config.yaml configuration file is being used validate permissions set to 600 or more restrictive (Automated)

- `cluster` — `no mapping`

## `kube-bench/5.2.2` — Privileged containers may be admitted

- `kyverno/block_privileged.yaml` — `cluster` — `follow-up required`

## `kube-bench/5.2.3` — Containers may share the host process ID namespace

- `kyverno/block_hostpid.yaml` — `cluster` — `follow-up required`

## `kube-bench/5.2.5` — Containers may share the host network namespace

- `kyverno/block_hostnet.yaml` — `cluster` — `follow-up required`

## `kube-bench/5.2.7` — Root containers may be admitted

- `kyverno/require_nonroot.yaml` — `cluster` — `follow-up required`

## `kube-bench/5.2.11` — Containers may mount hostPath volumes

- `kyverno/block_hostpath.yaml` — `cluster` — `follow-up required`
