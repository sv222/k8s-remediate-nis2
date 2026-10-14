# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# This adds one narrow RDP (tcp/3389) rule only. It does not remove existing rules.
# NOT FIXED BY THIS FILE: the internet-open rule of {{ .ResourceID }} stays in place and the finding stays open
# until you delete it (import the rule into state and remove it from code, or revoke it with the AWS CLI).
# Set rdp_allowed_cidr["{{ .ResourceID }}"] (see variables_sg_rdp.tf). Terraform stops with an error if the key is missing.
resource "aws_vpc_security_group_ingress_rule" "restricted_rdp_{{ .SanitizedResourceID }}" {
  region            = "{{ .Region }}"
  security_group_id = "{{ .ResourceID }}"
  description       = "Restricted RDP ingress replacing an internet-open rule"
  cidr_ipv4         = var.rdp_allowed_cidr["{{ .ResourceID }}"]
  ip_protocol       = "tcp"
  from_port         = 3389
  to_port           = 3389
}
