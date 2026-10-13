# k8s-remediate-nis2

**Prowler finds the problems — this tool generates the fixes.**

Parses Prowler v4 / kube-bench JSON output and emits ready-to-apply
Kyverno policies and Terraform snippets, mapped to NIS2 Art. 21(2)(a)–(j)
and DORA Chapter II articles, plus an auditor-facing evidence report.

    k8s-remediate-nis2 remediate --prowler prowler.json --out remediation/
    k8s-remediate-nis2 remediate --kube-bench bench.json --export-evidence

> Technical Remediation & Evidence Assistant for NIS2/DORA. This tool does not
> certify compliance; risk acceptance remains with the client's management.

Apache-2.0.
