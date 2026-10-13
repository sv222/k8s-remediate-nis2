# Remediation for: Security group open to the internet on all ports
# Articles: NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, ISO27001:2022 A.8.20
# This adds a narrow rule only. It does not remove existing rules.
# Next step: delete every internet-open ingress rule of sg-0a1b2c3d4e5f60718
# (import the rule into state and remove it from code, or revoke it with the AWS CLI), then apply.
# Set var.allowed_cidr and var.allowed_port (see variables_sg_ingress.tf).
resource "aws_vpc_security_group_ingress_rule" "restricted_sg-0a1b2c3d4e5f60718" {
  security_group_id = "sg-0a1b2c3d4e5f60718"
  description       = "Restricted ingress replacing an internet-open rule"
  cidr_ipv4         = var.allowed_cidr
  ip_protocol       = "tcp"
  from_port         = var.allowed_port
  to_port           = var.allowed_port
}
