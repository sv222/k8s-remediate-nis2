# Remediation for: GuardDuty detector is not enabled in the region
# Articles: NIS2 Art.21(2)(b), DORA Art.10, DORA RTS 2024/1774 Art.12, NIS2 CIR 2024/2690 Annex 3.2, ISO27001:2022 A.8.15, ISO27001:2022 A.8.16
# GuardDuty is per region. This file handles eu-west-1 only.
# A region can have only one detector. If one exists but is suspended, do not apply this file: import it
# (terraform import aws_guardduty_detector.enabled_000000000000_eu-west-1 DETECTOR_ID) and then apply.
# GuardDuty is charged by the volume of analyzed events. A 30-day free trial applies to new detectors.
resource "aws_guardduty_detector" "enabled_000000000000_eu-west-1" {
  region = "eu-west-1"
  enable = true
}
