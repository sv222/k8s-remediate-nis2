# k8s-remediate-nis2: NIS2 remediation for Kubernetes and AWS

[![CI](https://github.com/sv222/k8s-remediate-nis2/actions/workflows/ci.yml/badge.svg)](https://github.com/sv222/k8s-remediate-nis2/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Prowler finds the problems. This tool generates the fixes.**

`k8s-remediate-nis2` generates Kyverno and Terraform fixes for NIS2 failed
checks from Prowler and kube-bench reports. Each fix is mapped to NIS2 Article
21, DORA and ISO 27001 references. It can also write an evidence report for
auditors. It is a single Go binary.

> Technical Remediation & Evidence Assistant for NIS2/DORA. This tool does not certify compliance; risk acceptance remains with the client's management.

> **Important:** The NIS2, DORA and ISO 27001 mappings in this project have NOT
> been reviewed by legal or compliance experts. Do not use them as legal or
> audit advice. DORA Art.9 applies only to financial entities.

## What is this tool?

It is a small Go CLI. It is not a scanner. Run your scanner first, then give
the report to this tool. It is complementary to Prowler and kube-bench.

- Input: Prowler JSON and kube-bench JSON.
- Output: Kyverno `ClusterPolicy` files, Terraform files, `mapping.md`, and
  optionally `evidence.md`.
- Only `FAIL` findings are processed.

## Install

With Go:

```sh
go install github.com/sv222/k8s-remediate-nis2/cmd/k8s-remediate-nis2@latest
```

Build from source:

```sh
git clone https://github.com/sv222/k8s-remediate-nis2.git
cd k8s-remediate-nis2
make build
./bin/k8s-remediate-nis2 --version
```

## Quickstart: generate fixes from a Prowler or kube-bench report

```sh
prowler aws -M json-ocsf
k8s-remediate-nis2 remediate --prowler prowler.ocsf.json --out remediation/

kube-bench --json > bench.json
k8s-remediate-nis2 remediate --kube-bench bench.json --export-evidence
```

You can pass both `--prowler` and `--kube-bench` in one run.

| Flag | Meaning | Default |
|---|---|---|
| `--prowler` | Prowler JSON report | none |
| `--kube-bench` | kube-bench JSON report | none |
| `--out` | Output directory | `./remediation` |
| `--export-evidence` | Also write `evidence.md` | off |

At least one of `--prowler` or `--kube-bench` is required.

The command prints one summary line, for example:

```text
failed findings: 6, files written: 6, output: remediation/
```

Example `mapping.md` from a run with one Prowler and one kube-bench report:

```text
| Scanner | Check | Resource | Articles | Generated | Status | Note |
|---|---|---|---|---|---|---|
| prowler | s3_bucket_level_public_access_block | company-frontend-assets | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__company-frontend-assets.tf | remediated |  |
| kube-bench | 1.1.12 | cluster |  |  | no mapping |  |
| kube-bench | 5.2.2 | cluster | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.2 | kyverno/block_privileged.yaml | remediated |  |
```

## Supported scanner input formats

- Prowler `json-ocsf` (`prowler -M json-ocsf`).
- Prowler legacy `json` (`prowler -M json`, written by Prowler 3 only; Prowler 4 and 5 have no such mode).
- kube-bench JSON output.

Prowler AWS Security Finding Format (`json-asff`) is not supported. Re-run
Prowler with `-M json-ocsf`.

kube-bench mappings depend on the benchmark version in the report. These
versions are mapped: `cis-1.5` to `cis-1.12` (also `cis-1.20`, `cis-1.23`,
`cis-1.24`, `cis-1.6-k3s`), `eks-1.0.1` to `eks-1.8.0`, `aks-1.0`, `aks-1.7`,
`aks-1.8`, `gke-1.2.0` and `rke2-cis-1.7` to `rke2-cis-1.24`. The IDs are
checked against the kube-bench 0.16.0 config.

kube-bench marks the pod security controls (privileged, host network, root
containers) as manual checks, so it reports them as `WARN`, never `FAIL`. The
tool treats a manual `WARN` as a gap and generates the Kyverno policy for the
mapped controls.

## Supported checks

| Scanner | Check | NIS2 / DORA / ISO references | Generated file |
|---|---|---|---|
| prowler | `s3_bucket_level_public_access_block` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | `terraform/s3_public_access_block__<bucket>.tf` |
| prowler | `s3_bucket_public_access` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | `terraform/s3_public_access_block__<bucket>.tf` |
| prowler | `s3_bucket_public_list_acl` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | `terraform/s3_public_access_block__<bucket>.tf` |
| prowler | `s3_bucket_default_encryption` | NIS2 Art.21(2)(h), DORA Art.9, ISO27001:2022 A.8.24 | `terraform/s3_encryption__<bucket>.tf` |
| prowler | `s3_bucket_kms_encryption` | NIS2 Art.21(2)(h), DORA Art.9, ISO27001:2022 A.8.24 | `terraform/s3_encryption_kms__<bucket>.tf`, `terraform/variables_kms_key.tf` |
| prowler | `ec2_securitygroup_allow_ingress_from_internet_to_any_port` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | `terraform/sg_restrict_ingress__<sg-id>.tf`, `terraform/variables_sg_ingress.tf` |
| prowler | `ec2_securitygroup_allow_ingress_from_internet_to_all_ports` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | `terraform/sg_restrict_ingress__<sg-id>.tf`, `terraform/variables_sg_ingress.tf` |
| prowler | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | `terraform/sg_restrict_ingress__<sg-id>.tf`, `terraform/variables_sg_ingress.tf` |
| prowler | `ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | `terraform/sg_restrict_ingress__<sg-id>.tf`, `terraform/variables_sg_ingress.tf` |
| prowler | `ec2_securitygroup_allow_ingress_from_internet_to_high_risk_tcp_ports` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | `terraform/sg_restrict_ingress__<sg-id>.tf`, `terraform/variables_sg_ingress.tf` |
| prowler | `s3_bucket_public_write_acl` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | `terraform/s3_public_access_block__<bucket>.tf` |
| prowler | `s3_bucket_policy_public_write_access` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | `terraform/s3_public_access_block__<bucket>.tf` |
| prowler | `eks_cluster_not_publicly_accessible` | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | none (guidance text in `mapping.md`) |
| kube-bench | 5.2.2 (cis-1.7 and later), 5.2.1 (cis-1.5, cis-1.6), 4.2.1 (eks, aks): privileged containers | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.2 | `kyverno/block_privileged.yaml` |
| kube-bench | 5.2.5 (cis-1.7 and later), 5.2.4 (cis-1.5, cis-1.6), 4.2.4 (eks, aks): host network | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.22 | `kyverno/block_hostnet.yaml` |
| kube-bench | 5.2.7 (cis-1.7 and later), 5.2.6 (cis-1.5, cis-1.6), 4.2.6 (eks-1.0.1 to eks-1.2.0): root containers | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.2 | `kyverno/require_nonroot.yaml` |

The source of truth is `mapping/mappings.yaml`.

## FAQ

### How do I fix a failed Prowler check like s3_bucket_level_public_access_block?

Run `prowler aws -M json-ocsf`, then run `k8s-remediate-nis2 remediate --prowler prowler.ocsf.json`.
The tool writes a Terraform file for each bucket, for example
`terraform/s3_public_access_block__<bucket>.tf`. Review it before `terraform apply`.

### Can I turn a Prowler report into Terraform snippets?

Yes, for the checks listed in "Supported checks". Other failed checks are
listed in `mapping.md` as `no mapping` or `guidance only`.

### How do I fix kube-bench 5.2.2, 5.2.5 and 5.2.7 with Kyverno?

Run `kube-bench --json > bench.json`, then
`k8s-remediate-nis2 remediate --kube-bench bench.json`. You get Kyverno
`ClusterPolicy` files for privileged containers (5.2.2), host network (5.2.5)
and root containers (5.2.7). The policies start in `Audit` mode.

### How do I fix ec2_securitygroup_allow_ingress_from_internet_to_any_port?

The tool writes a Terraform rule for a narrow ingress. You set `var.allowed_cidr`
and `var.allowed_port` and remove the open rules yourself.

### What about eks_cluster_not_publicly_accessible?

There is no code fix. `mapping.md` shows guidance text with status `guidance only`.

### Does it create an NIS2 evidence report for auditors?

Yes. Use `--export-evidence` to write `evidence.md`. It has counts, the SHA-256
of each input file and the full table. It does not certify compliance.

### Does DORA Art.9 apply to me?

Only if you are a financial entity. The DORA references in the mappings are
unreviewed.

### Is it a scanner or a Prowler alternative?

No. It does not scan. It works after Prowler and kube-bench.

## Output layout

```text
remediation/
  kyverno/      cluster-wide policies, one file per policy
  terraform/    one file per resource, plus shared variable files
  mapping.md    every failed finding and its status
  evidence.md   auditor report (only with --export-evidence)
```

- Terraform files are named `<template>__<resource>.tf`.
- Kyverno policies are rendered once for the whole cluster.
- A finding gets one status: `remediated`, `guidance only`, `no mapping`, or
  `skipped: invalid resource id`.
- `evidence.md` has counts, the SHA-256 of each input file, and the full table.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success. This includes runs where some findings have no mapping. |
| 2 | Error, for example a missing flag, an unreadable file or an unsupported format. |

## Safety notes

- Kyverno policies start in `Audit` mode. Read the policy reports, then change
  `validationFailureAction` to `Enforce`.
- Policies skip `kube-system`, `kube-public`, `kube-node-lease` and `kyverno`.
- Review all generated Terraform before you run `terraform apply`.
- The security group snippet only adds a narrow rule. You must set
  `var.allowed_cidr` and `var.allowed_port`, and remove the internet-open rules
  yourself.
- Resource IDs are checked before they reach a template. Invalid IDs are
  skipped and listed in `mapping.md`.

## Limitations

- The mapping set is small. Many failed checks will show `no mapping`.
- It is not a scanner. It does not look at your cloud or cluster.
- Article references are a technical aid. They are not legal advice.
- It does not certify compliance with NIS2, DORA or ISO 27001.
- The mappings are not reviewed by legal or compliance experts.
- DORA Art.9 applies only to financial entities.

## Disclaimer

Technical Remediation & Evidence Assistant for NIS2/DORA. This tool does not certify compliance; risk acceptance remains with the client's management.

## License

Apache-2.0. See `LICENSE`.
