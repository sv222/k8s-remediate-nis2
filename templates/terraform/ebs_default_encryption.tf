# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# This setting is per region. This file handles {{ .Region }} only. It affects new volumes and
# snapshot copies. Existing unencrypted volumes stay unencrypted: migrate them separately.
# New volumes use the AWS-managed key aws/ebs. Set the default key separately if you need a CMK.
provider "aws" {
  alias  = "ebs_{{ .SanitizedResourceID }}"
  region = "{{ .Region }}"
}

resource "aws_ebs_encryption_by_default" "enabled_{{ .SanitizedResourceID }}" {
  provider = aws.ebs_{{ .SanitizedResourceID }}
  enabled  = true
}
