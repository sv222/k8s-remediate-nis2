# Remediation summary

> Nothing was applied. These are proposals; apply them, then re-scan to confirm the findings are fixed.

## `prowler/core_minimize_privileged_containers` — Privileged containers may be admitted

- `kyverno/block_privileged.yaml` — `nis2demo/Pod/bad-privileged` — `follow-up required`
- `kyverno/block_privileged.yaml` — `kube-system/Pod/kube-proxy-kgdcn` — `follow-up required`

## `prowler/core_minimize_hostPID_containers` — Containers may share the host process ID namespace

- `kyverno/block_hostpid.yaml` — `nis2demo/Pod/bad-hostpid` — `follow-up required`

## `prowler/core_minimize_hostIPC_containers` — Containers may share the host IPC namespace

- `kyverno/block_hostipc.yaml` — `nis2demo/Pod/bad-hostipc` — `follow-up required`

## `prowler/core_minimize_hostNetwork_containers` — Containers may share the host network namespace

- `kyverno/block_hostnet.yaml` — `nis2demo/Pod/bad-hostnet` — `follow-up required`
- `kyverno/block_hostnet.yaml` — `kube-system/Pod/kindnet-nvsmq` — `follow-up required`

## `prowler/core_minimize_root_containers_admission` — Root containers may be admitted

- `kyverno/require_nonroot.yaml` — `nis2demo/Pod/bad-root` — `follow-up required`

## `prowler/core_minimize_allowPrivilegeEscalation_containers` — Containers may allow privilege escalation

- `kyverno/block_privilege_escalation.yaml` — `nis2demo/Pod/bad-privesc` — `follow-up required`

## `prowler/core_minimize_hostpath_volume_mounts` — Containers may mount hostPath volumes

- `kyverno/block_hostpath.yaml` — `nis2demo/Pod/bad-hostpath` — `follow-up required`
- `kyverno/block_hostpath.yaml` — `kube-system/Pod/kube-proxy-kgdcn` — `follow-up required`

## `prowler/core_readonly_root_filesystem_enabled` — Containers can write to their root filesystem

- `nis2demo/Pod/bad-privileged` — `guidance only`

## `prowler/core_seccomp_profile_docker_default` — Containers do not use a seccomp profile

- `nis2demo/Pod/bad-privileged` — `guidance only`

## `prowler/core_minimize_containers_added_capabilities` — Containers add Linux capabilities

- `kube-system/Pod/coredns-674b8bbfcf-ks962` — `guidance only`

## `prowler/core_cpu_limits_set` — Pod containers have CPU limits set

- `nis2demo/KubernetesPod/bad-privileged` — `no mapping`

## `prowler/apiserver_audit_log_path_set` — API server audit logging is not configured

- `kube-system/Pod/kube-apiserver-demo-control-plane` — `guidance only`

## `prowler/apiserver_audit_log_maxage_set` — API server audit logs are kept for too long or not rotated

- `kube-system/Pod/kube-apiserver-demo-control-plane` — `guidance only`

## `prowler/apiserver_audit_log_maxbackup_set` — API server keeps too few audit log backups

- `kube-system/Pod/kube-apiserver-demo-control-plane` — `guidance only`

## `prowler/apiserver_audit_log_maxsize_set` — API server audit log files are not size limited

- `kube-system/Pod/kube-apiserver-demo-control-plane` — `guidance only`

## `prowler/apiserver_encryption_provider_config_set` — Kubernetes secrets are not encrypted at rest

- `kube-system/Pod/kube-apiserver-demo-control-plane` — `guidance only`

## `prowler/apiserver_disable_profiling` — API server profiling endpoints are enabled

- `kube-system/Pod/kube-apiserver-demo-control-plane` — `guidance only`

## `prowler/apiserver_service_account_lookup_true` — API server does not validate service account tokens

- `kube-system/Pod/kube-apiserver-demo-control-plane` — `guidance only`

## `prowler/apiserver_always_pull_images_plugin` — AlwaysPullImages admission plugin is not enabled

- `kube-system/Pod/kube-apiserver-demo-control-plane` — `guidance only`

## `prowler/controllermanager_disable_profiling` — Controller manager profiling endpoints are enabled

- `kube-system/Pod/kube-controller-manager-demo-control-plane` — `guidance only`

## `prowler/scheduler_profiling` — Scheduler profiling endpoints are enabled

- `kube-system/Pod/kube-scheduler-demo-control-plane` — `guidance only`

## `prowler/rbac_minimize_wildcard_use_roles` — Roles use wildcards

- `kind-demo` — `guidance only`

## `prowler/rbac_minimize_secret_access` — Roles grant broad access to secrets

- `kind-demo` — `guidance only`

## `prowler/kubelet_tls_cert_and_key` — Kubelet has TLS certificate and private key files configured

- `kube-system/ConfigMap/kubelet-config` — `no mapping`
