# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added

- `remediate` command with `--prowler`, `--kube-bench`, `--out` and `--export-evidence`.
- Parsers for Prowler `json-ocsf`, Prowler legacy `json` and kube-bench JSON.
- Seed mapping of checks to NIS2, DORA and ISO 27001 references.
- Kyverno policy templates (Audit mode) for privileged, host network and root containers.
- Terraform templates for S3 public access block, S3 encryption and security group ingress.
- `mapping.md` summary and `evidence.md` report with input SHA-256 hashes.

[Unreleased]: https://github.com/nis2rem/k8s-remediate-nis2/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nis2rem/k8s-remediate-nis2/releases/tag/v0.1.0
