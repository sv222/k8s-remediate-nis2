# Remediation summary

> Nothing was applied. These are proposals; apply them, then re-scan to confirm the findings are fixed.

## `prowler/s3_bucket_public_access` — S3 bucket publicly accessible

- `terraform/s3_public_access_block__acme-public-logs.tf` — `acme-public-logs`, `us-east-1`, account `000000000000` — `code generated`

## `prowler/s3_bucket_kms_encryption` — S3 bucket without SSE-KMS default encryption

- `terraform/s3_encryption_kms__acme-backup-dump.tf` — `acme-backup-dump`, `us-east-1`, account `000000000000` — `follow-up required`
- `terraform/variables_kms_key.tf` — `acme-backup-dump`, `us-east-1`, account `000000000000` — `follow-up required`

## `prowler/eks_cluster_not_publicly_accessible` — EKS API server endpoint open to the internet

- `acme-eks`, `us-east-1`, account `000000000000` — `guidance only`

## `prowler/ec2_ebs_default_encryption` — EBS default encryption is not enabled

- `terraform/ebs_default_encryption__000000000000_us-east-1.tf` — `000000000000`, `us-east-1`, account `000000000000` — `follow-up required`

## `prowler/core_minimize_privileged_containers` — Privileged containers may be admitted

- `kyverno/block_privileged.yaml` — `nis2demo/Pod/bad-privileged` — `follow-up required`

## `prowler/core_minimize_hostNetwork_containers` — Containers may share the host network namespace

- `kyverno/block_hostnet.yaml` — `kube-system/Pod/kindnet-nvsmq` — `follow-up required`

## `prowler/core_minimize_hostpath_volume_mounts` — Containers may mount hostPath volumes

- `kyverno/block_hostpath.yaml` — `nis2demo/Pod/bad-hostpath` — `follow-up required`

## `prowler/apiserver_encryption_provider_config_set` — Kubernetes secrets are not encrypted at rest

- `kube-system/Pod/kube-apiserver-demo-control-plane` — `guidance only`

## `prowler/rbac_minimize_wildcard_use_roles` — Roles use wildcards

- `kind-demo` — `guidance only`

## `prowler/core_cpu_limits_set` — Pod containers have CPU limits set

- `nis2demo/KubernetesPod/bad-privileged` — `no mapping`
