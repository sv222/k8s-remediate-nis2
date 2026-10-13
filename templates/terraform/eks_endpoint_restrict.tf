# Remediation for: {{ .Title }}
# Articles: {{ range .Articles }}{{ . }} {{ end }}
resource "aws_eks_cluster" "remediation_{{ .SanitizedResourceID }}" {
  # v1 scaffolding: patch-in-place via `terraform import aws_eks_cluster.<name> {{ .ResourceID }}`
  # then set endpoint config below and apply.
  name = "{{ .ResourceID }}"

  vpc_config {
    endpoint_public_access = false
  }

  role_arn = "ARN_PLACEHOLDER"
}
