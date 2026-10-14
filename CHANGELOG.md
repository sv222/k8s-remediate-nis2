# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Security group fix: SSH and RDP have their own templates with a fixed port and a CIDR per security group ID (`ssh_allowed_cidr`, `rdp_allowed_cidr`). Before, all flagged groups shared one port and one CIDR, so a group flagged only for RDP could get SSH. Checks that do not say which port is open (`..._to_any_port`, `..._to_all_ports`, `..._to_high_risk_tcp_ports`) are now guidance only.
- Kyverno policies for privileged and root containers also match `pods/ephemeralcontainers`, so `kubectl debug` cannot add a privileged container in `Deny` mode. Not tested on a live cluster.
- Markdown reports show check, resource, region and file names as code spans with a strict character set. Other text is escaped. A crafted resource ID can no longer add links or images to `mapping.md` or `evidence.md`.
- Resource IDs that contain `0.0.0.0/0` or `::/0` are rejected.

### Changed

- Row statuses are now `code generated`, `follow-up required`, `guidance only`, `no mapping` and `skipped`. The old status `remediated` and the count `Remediated: N` are gone: they counted written files, not fixed findings. `evidence.md` says that nothing was applied and lists what stays open per row (open security group rule, Audit-mode policies, existing objects and volumes that stay unencrypted).
- The output directory must be empty. Use `--force` to replace the files of a previous run. Only files listed in the old `manifest.json` are removed.
- Input with findings of more than one AWS account is refused. Run the tool once per account.
- Muted Prowler findings (OCSF `status` `Suppressed`, `status_id` 3, or legacy `Muted`) are not remediated. They are counted and listed in `evidence.md`.
- `evidence.md` counts only `FAIL` findings as failed. PASS, MANUAL, other statuses, suppressed findings and duplicate records are reported separately. Duplicate records are ignored.
- `evidence.md` has the SHA-256 of the bytes that were parsed (not of a second read), the SHA-256 of every generated file, the mapping version and SHA-256, the account, and a UTC time with a note about its source.
- `manifest.json` lists every written file with its SHA-256, the tool version and the mapping version.
- Tool version falls back to the Go build info, so `go install` builds report the module version instead of `dev`.
- Generated Terraform gets `versions.tf` with a provider constraint (`>= 6.0, < 7.0`).
- A shared file gets the titles and articles of every check that maps to it, not only the first.
- `s3_bucket_default_encryption` and `s3_bucket_kms_encryption` on one bucket write only the KMS file. Before they wrote two conflicting resources.
- File and resource names are lower case. A name that changes (case, special characters, length) gets an 8 character hash, so names never collide on case-insensitive file systems.
- KMS template: warning about log delivery and `kms:Decrypt`, one key per region (`kms_key_arns`), and `kms_excluded_buckets` for log target buckets.
- Block Public Access template starts with a warning.
- Security group and KMS files set the `region` argument (AWS provider 6.0 or later).
- ISO 27001 `A.8.2` (privileged access rights) was replaced by `A.8.9` (configuration management) for privileged and root containers. Added references to Delegated Regulation (EU) 2024/1774 (DORA RTS) and Implementing Regulation (EU) 2024/2690. The mapping is still not reviewed by experts.

### Added

- `--force` flag.
- Native Go fuzz tests for the Prowler and kube-bench parsers, resource ID sanitizing, the template renderer and Markdown escaping. Property tests for CIDRs, file names and report shape. `make fuzz` runs them.
- `make tf-check` (`scripts/tfcheck.sh`): `terraform fmt -check` and `validate` on the generated code of the test reports and of a random-ID corpus.
- CI jobs for `staticcheck`, `govulncheck`, `make policy-test` and `make tf-check`. Dependabot for Go modules and GitHub Actions.
- Release: GitHub Actions pinned by commit SHA, pinned GoReleaser, `-trimpath`, SBOM (Syft) and keyless cosign signature of `checksums.txt`. These run only on a tag and were not run locally.

## [0.2.0] - 2026-10-14

### Added

- `make policy-test`: checks the three Kyverno templates with the Kyverno CLI against good and bad pod manifests.
- Terraform templates for `s3_bucket_secure_transport_policy` (deny plain HTTP), `s3_bucket_server_access_logging_enabled`, `s3_bucket_acl_prohibited` and `ec2_ebs_default_encryption` (one file per region). The risky templates start with a warning header.
- Guidance-only entries for `eks_cluster_private_nodes_enabled`, `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_allow_ingress_tcp_port_22` and `ec2_networkacl_allow_ingress_tcp_port_3389`. Network ACL changes are stateless and can lock out users, so no code is generated.
- `regional` mapping option: the template gets the finding region and the file name includes it.
- `scripts/e2e.sh` and `make e2e`: Docker-based end-to-end test with the Floci AWS emulator, Prowler 5.45, Terraform and this CLI.
- `.github/workflows/e2e.yml`: manual and weekly run of the end-to-end test.

### Changed

- kube-bench test fixtures are real kube-bench 0.16.0 output (`cis-1.12`, Kubernetes 1.37, kind), with the node IP and cluster name removed.
- kube-bench benchmark IDs also cover `ack-1.0`, `cis-1.24-microk8s`, `gke-1.0`, `k3s-cis-*`, `rke-cis-*`, `rh-*` and `tkgi-1.2.53`.
- Kyverno templates use `ValidatingPolicy` (`policies.kyverno.io/v1`). Kyverno 1.19 deprecates `ClusterPolicy` and Kyverno 1.20 removes it.
- The kube-bench pod security controls are processed when they are reported as manual `WARN`.
- kube-bench benchmark IDs cover the current CIS, EKS, AKS, GKE and RKE2 benchmark versions.
- `var.allowed_cidr` rejects wide public ranges: it accepts private IPv4 ranges, or public ranges with prefix length 24 or longer.
- Prowler 5 security group checks for all ports, SSH, RDP and high-risk ports and the S3 public write checks are mapped.

### Fixed

- kube-bench manual controls whose `type` is empty were skipped. With real `cis-1.12` output this dropped privileged containers (5.2.2) and host network (5.2.5). The `(Manual)` and `(Not Scored)` text endings are now detected too.

## [0.1.0] - 2026-10-13

### Added

- `remediate` command with `--prowler`, `--kube-bench`, `--out` and `--export-evidence`.
- Parsers for Prowler `json-ocsf`, Prowler legacy `json` and kube-bench JSON.
- Seed mapping of checks to NIS2, DORA and ISO 27001 references.
- Kyverno policy templates (Audit mode) for privileged, host network and root containers.
- Terraform templates for S3 public access block, S3 encryption and security group ingress.
- `mapping.md` summary and `evidence.md` report with input SHA-256 hashes.

[Unreleased]: https://github.com/sv222/k8s-remediate-nis2/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/sv222/k8s-remediate-nis2/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sv222/k8s-remediate-nis2/releases/tag/v0.1.0
