# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# WARNING: this setting is per region. This file handles {{ .Region }} only. It blocks all public sharing of EBS snapshots
# in the region. Snapshots that are already public become private at once, and users of those snapshots lose access.
# Check them first: aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all --region {{ .Region }}
resource "aws_ebs_snapshot_block_public_access" "block_all_{{ .SanitizedResourceID }}" {
  region = "{{ .Region }}"
  state  = "block-all-sharing"
}
