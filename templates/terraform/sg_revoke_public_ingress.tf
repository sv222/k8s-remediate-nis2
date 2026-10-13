# Remediation for: {{ .Title }}
# Articles: {{ range .Articles }}{{ . }} {{ end }}
resource "aws_security_group_rule" "deny_public_{{ .SanitizedResourceID }}" {
  type              = "ingress"
  security_group_id = "{{ .ResourceID }}"
  description       = "NIS2 remediation: revoke 0.0.0.0/0 ingress"
  cidr_blocks       = ["0.0.0.0/0"]
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  # NOTE: aws_security_group_rule cannot deny; import-then-remove pattern:
  # run `terraform import` for existing rule then delete it. This block is scaffolding.
}
