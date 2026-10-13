# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
