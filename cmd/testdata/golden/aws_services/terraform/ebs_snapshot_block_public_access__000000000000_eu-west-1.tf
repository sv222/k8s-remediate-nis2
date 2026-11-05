# Remediation for: EBS snapshot block public access is not enabled
# Articles: NIS2 Art.21(2)(i), NIS2 Art.21(2)(g), DORA Art.9, DORA RTS 2024/1774 Art.21, NIS2 CIR 2024/2690 Annex 11.1, ISO27001:2022 A.8.3
# WARNING: this setting is per region. This file handles eu-west-1 only. It blocks all public sharing of EBS snapshots
# in the region. Snapshots that are already public become private at once, and users of those snapshots lose access.
# Check them first: aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all --region eu-west-1
resource "aws_ebs_snapshot_block_public_access" "block_all_000000000000_eu-west-1" {
  region = "eu-west-1"
  state  = "block-all-sharing"
}
