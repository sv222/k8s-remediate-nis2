# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# AWS Config is per region. This file handles {{ .Region }} only. A region can have only one recorder and one delivery channel.
# If they exist, do not apply this file: import them or change them in place. Check: aws configservice describe-configuration-recorders --region {{ .Region }}
# The role in var.config_role_arn and the bucket in var.config_bucket (see variables_config.tf) must exist.
# The recorder records all supported resource types of the region. Global resource types are not included, so
# record them in one region only. AWS Config is charged per configuration item recorded.
resource "aws_config_configuration_recorder" "nis2_{{ .SanitizedResourceID }}" {
  region   = "{{ .Region }}"
  name     = "nis2-{{ .Region }}"
  role_arn = var.config_role_arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = false
  }
}

resource "aws_config_delivery_channel" "nis2_{{ .SanitizedResourceID }}" {
  region         = "{{ .Region }}"
  name           = "nis2-{{ .Region }}"
  s3_bucket_name = var.config_bucket

  depends_on = [aws_config_configuration_recorder.nis2_{{ .SanitizedResourceID }}]
}

resource "aws_config_configuration_recorder_status" "nis2_{{ .SanitizedResourceID }}" {
  region     = "{{ .Region }}"
  name       = aws_config_configuration_recorder.nis2_{{ .SanitizedResourceID }}.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.nis2_{{ .SanitizedResourceID }}]
}
