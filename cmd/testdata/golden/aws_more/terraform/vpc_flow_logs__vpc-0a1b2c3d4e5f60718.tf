# Remediation for: VPC flow logs are not enabled
# Articles: NIS2 Art.21(2)(b), DORA Art.10, DORA RTS 2024/1774 Art.12, NIS2 CIR 2024/2690 Annex 3.2, ISO27001:2022 A.8.15, ISO27001:2022 A.8.16
# Sends flow logs of all traffic of vpc-0a1b2c3d4e5f60718 to the S3 bucket in var.flow_log_bucket_arn (see variables_flow_log.tf).
# The bucket must exist, and its bucket policy must let delivery.logs.amazonaws.com write. AWS adds that statement
# only if you may change the bucket policy. Flow logs are charged by volume: set a lifecycle rule on the bucket.
resource "aws_flow_log" "vpc_vpc-0a1b2c3d4e5f60718" {
  region               = "us-east-1"
  vpc_id               = "vpc-0a1b2c3d4e5f60718"
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = var.flow_log_bucket_arn
}
