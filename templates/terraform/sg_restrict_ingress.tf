# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# This adds a narrow rule only. It does not remove existing rules.
# Next step: delete every internet-open ingress rule of {{ .ResourceID }}
# (import the rule into state and remove it from code, or revoke it with the AWS CLI), then apply.
# Set var.allowed_cidr and var.allowed_port (see variables_sg_ingress.tf).
resource "aws_vpc_security_group_ingress_rule" "restricted_{{ .SanitizedResourceID }}" {
  security_group_id = "{{ .ResourceID }}"
  description       = "Restricted ingress replacing an internet-open rule"
  cidr_ipv4         = var.allowed_cidr
  ip_protocol       = "tcp"
  from_port         = var.allowed_port
  to_port           = var.allowed_port
}
