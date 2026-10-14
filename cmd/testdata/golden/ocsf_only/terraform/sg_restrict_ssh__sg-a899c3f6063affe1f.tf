# Remediation for: Security group open to the internet on SSH (port 22)
# Articles: NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.13, NIS2 CIR 2024/2690 Annex 6.7, ISO27001:2022 A.8.20
# This adds one narrow SSH (tcp/22) rule only. It does not remove existing rules.
# NOT FIXED BY THIS FILE: the internet-open rule of sg-a899c3f6063affe1f stays in place and the finding stays open
# until you delete it (import the rule into state and remove it from code, or revoke it with the AWS CLI).
# Set ssh_allowed_cidr["sg-a899c3f6063affe1f"] (see variables_sg_ssh.tf). Terraform stops with an error if the key is missing.
resource "aws_vpc_security_group_ingress_rule" "restricted_ssh_sg-a899c3f6063affe1f" {
  region            = "us-east-1"
  security_group_id = "sg-a899c3f6063affe1f"
  description       = "Restricted SSH ingress replacing an internet-open rule"
  cidr_ipv4         = var.ssh_allowed_cidr["sg-a899c3f6063affe1f"]
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}
