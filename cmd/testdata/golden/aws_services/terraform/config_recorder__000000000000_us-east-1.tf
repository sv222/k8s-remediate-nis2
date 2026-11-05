# Remediation for: AWS Config recorder is not enabled in the region
# Articles: NIS2 Art.21(2)(b), DORA Art.10, DORA RTS 2024/1774 Art.12, NIS2 CIR 2024/2690 Annex 3.2, ISO27001:2022 A.8.15, ISO27001:2022 A.8.9
# AWS Config is per region. This file handles us-east-1 only. A region can have only one recorder and one delivery channel.
# If they exist, do not apply this file: import them or change them in place. Check: aws configservice describe-configuration-recorders --region us-east-1
# The role in var.config_role_arn and the bucket in var.config_bucket (see variables_config.tf) must exist.
# The recorder records all supported resource types of the region. Global resource types are not included, so
# record them in one region only. AWS Config is charged per configuration item recorded.
resource "aws_config_configuration_recorder" "nis2_000000000000_us-east-1" {
  region   = "us-east-1"
  name     = "nis2-us-east-1"
  role_arn = var.config_role_arn

  recording_group {
    all_supported                 = true
    include_global_resource_types = false
  }
}

resource "aws_config_delivery_channel" "nis2_000000000000_us-east-1" {
  region         = "us-east-1"
  name           = "nis2-us-east-1"
  s3_bucket_name = var.config_bucket

  depends_on = [aws_config_configuration_recorder.nis2_000000000000_us-east-1]
}

resource "aws_config_configuration_recorder_status" "nis2_000000000000_us-east-1" {
  region     = "us-east-1"
  name       = aws_config_configuration_recorder.nis2_000000000000_us-east-1.name
  is_enabled = true

  depends_on = [aws_config_delivery_channel.nis2_000000000000_us-east-1]
}
