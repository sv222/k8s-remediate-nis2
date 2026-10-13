# Remediation mapping

| Scanner | Check | Resource | Articles | Generated | Status | Note |
|---|---|---|---|---|---|---|
| prowler | s3_bucket_level_public_access_block | company-frontend-assets | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.3 | terraform/s3_public_access_block__company-frontend-assets.tf | remediated |  |
| prowler | ec2_securitygroup_allow_ingress_from_internet_to_any_port | sg-0a1b2c3d4e5f60718 | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20 | terraform/sg_restrict_ingress__sg-0a1b2c3d4e5f60718.tf, terraform/variables_sg_ingress.tf | remediated |  |
| kube-bench | 1.1.12 | cluster |  |  | no mapping |  |
| kube-bench | 5.2.2 | cluster | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.2 | kyverno/block_privileged.yaml | remediated |  |
| kube-bench | 5.2.5 | cluster | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.22 | kyverno/block_hostnet.yaml | remediated |  |
| kube-bench | 5.2.7 | cluster | NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.2 | kyverno/require_nonroot.yaml | remediated |  |
