# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Terraform templates for `s3_bucket_secure_transport_policy` (deny plain HTTP), `s3_bucket_server_access_logging_enabled`, `s3_bucket_acl_prohibited` and `ec2_ebs_default_encryption` (one file per region). The risky templates start with a warning header.
- Guidance-only entries for `eks_cluster_private_nodes_enabled`, `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_allow_ingress_tcp_port_22` and `ec2_networkacl_allow_ingress_tcp_port_3389`. Network ACL changes are stateless and can lock out users, so no code is generated.
- `regional` mapping option: the template gets the finding region and the file name includes it.
- `scripts/e2e.sh` and `make e2e`: Docker-based end-to-end test with the Floci AWS emulator, Prowler 5.45, Terraform and this CLI.
- `.github/workflows/e2e.yml`: manual and weekly run of the end-to-end test.

### Changed

- Kyverno templates use `ValidatingPolicy` (`policies.kyverno.io/v1`). Kyverno 1.19 deprecates `ClusterPolicy` and Kyverno 1.20 removes it.
- The kube-bench pod security controls are processed when they are reported as manual `WARN`.
- kube-bench benchmark IDs cover the current CIS, EKS, AKS, GKE and RKE2 benchmark versions.
- `var.allowed_cidr` rejects wide public ranges: it accepts private IPv4 ranges, or public ranges with prefix length 24 or longer.
- Prowler 5 security group checks for all ports, SSH, RDP and high-risk ports and the S3 public write checks are mapped.

## [0.1.0] - 2026-10-13

### Added

- `remediate` command with `--prowler`, `--kube-bench`, `--out` and `--export-evidence`.
- Parsers for Prowler `json-ocsf`, Prowler legacy `json` and kube-bench JSON.
- Seed mapping of checks to NIS2, DORA and ISO 27001 references.
- Kyverno policy templates (Audit mode) for privileged, host network and root containers.
- Terraform templates for S3 public access block, S3 encryption and security group ingress.
- `mapping.md` summary and `evidence.md` report with input SHA-256 hashes.

[Unreleased]: https://github.com/sv222/k8s-remediate-nis2/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/sv222/k8s-remediate-nis2/releases/tag/v0.1.0
