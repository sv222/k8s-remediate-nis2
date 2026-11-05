# Remediation for: {{ .Title }}
# Articles: {{ range $i, $a := .Articles }}{{ if $i }}, {{ end }}{{ $a }}{{ end }}
# GuardDuty is per region. This file handles {{ .Region }} only.
# A region can have only one detector. If one exists but is suspended, do not apply this file: import it
# (terraform import aws_guardduty_detector.enabled_{{ .SanitizedResourceID }} DETECTOR_ID) and then apply.
# GuardDuty is charged by the volume of analyzed events. A 30-day free trial applies to new detectors.
resource "aws_guardduty_detector" "enabled_{{ .SanitizedResourceID }}" {
  region = "{{ .Region }}"
  enable = true
}
