# NIS2/DORA remediation: one multi-region CloudTrail trail for management events.
# WARNING: if another trail already logs management events, this trail is a second copy and AWS charges for it.
# Check the existing trails first: aws cloudtrail describe-trails. If one exists, turn on multi-region for it instead:
# aws cloudtrail update-trail --name TRAIL --is-multi-region-trail
# The bucket in var.cloudtrail_bucket (see variables_cloudtrail.tf) must exist and its bucket policy must let
# cloudtrail.amazonaws.com write, or the trail is not created. The home region of the trail is the provider region.
resource "aws_cloudtrail" "nis2_multi_region" {
  name                          = var.cloudtrail_name
  s3_bucket_name                = var.cloudtrail_bucket
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  enable_logging                = true
}
