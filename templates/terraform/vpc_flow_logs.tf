# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# Sends flow logs of all traffic of {{ .ResourceID }} to the S3 bucket in var.flow_log_bucket_arn (see variables_flow_log.tf).
# The bucket must exist, and its bucket policy must let delivery.logs.amazonaws.com write. AWS adds that statement
# only if you may change the bucket policy. Flow logs are charged by volume: set a lifecycle rule on the bucket.
resource "aws_flow_log" "vpc_{{ .SanitizedResourceID }}" {
  region               = "{{ .Region }}"
  vpc_id               = "{{ .ResourceID }}"
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = var.flow_log_bucket_arn
}
