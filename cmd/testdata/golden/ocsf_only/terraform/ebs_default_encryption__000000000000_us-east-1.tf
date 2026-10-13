# Remediation for: EBS default encryption is not enabled
# Articles: NIS2 Art.21(2)(h), DORA Art.9, ISO27001:2022 A.8.24
# This setting is per region. This file handles us-east-1 only. It affects new volumes and
# snapshot copies. Existing unencrypted volumes stay unencrypted: migrate them separately.
# New volumes use the AWS-managed key aws/ebs. Set the default key separately if you need a CMK.
provider "aws" {
  alias  = "ebs_000000000000_us-east-1"
  region = "us-east-1"
}

resource "aws_ebs_encryption_by_default" "enabled_000000000000_us-east-1" {
  provider = aws.ebs_000000000000_us-east-1
  enabled  = true
}
