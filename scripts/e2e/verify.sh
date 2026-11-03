#!/usr/bin/env bash
set -euo pipefail

case "${AWS_ENDPOINT_URL:-}" in
  http://localhost:*|http://127.0.0.1:*|http://*-floci:*) ;;
  *) echo "refusing to run: AWS_ENDPOINT_URL must point to the local emulator" >&2; exit 1 ;;
esac

policy=$(aws s3api get-bucket-policy --bucket nr-existing-policy --query Policy --output text)
echo "$policy" | grep -q KeepMe || { echo "existing policy statement KeepMe was lost" >&2; exit 1; }
echo "$policy" | grep -q DenyInsecureTransport || { echo "deny statement is missing" >&2; exit 1; }
echo "$policy" | grep -q '"aws:SecureTransport"' || { echo "SecureTransport condition is missing" >&2; exit 1; }
echo "ok: nr-existing-policy keeps KeepMe and has DenyInsecureTransport"

own=$(aws s3api get-bucket-ownership-controls --bucket nr-public-acl --query 'OwnershipControls.Rules[0].ObjectOwnership' --output text)
[ "$own" = "BucketOwnerEnforced" ] || { echo "ownership controls not enforced: $own" >&2; exit 1; }
echo "ok: nr-public-acl has BucketOwnerEnforced"

target=$(aws s3api get-bucket-logging --bucket nr-plain --query 'LoggingEnabled.TargetBucket' --output text)
[ "$target" = "nr-log-target" ] || { echo "logging target wrong: $target" >&2; exit 1; }
echo "ok: nr-plain logs to nr-log-target"

ebs=$(aws ec2 get-ebs-encryption-by-default --query EbsEncryptionByDefault --output text)
[ "$ebs" = "True" ] || [ "$ebs" = "true" ] || { echo "EBS default encryption is $ebs" >&2; exit 1; }
echo "ok: EBS default encryption is on"

sg_ports() {
  aws ec2 describe-security-groups --filters "Name=group-name,Values=$1" \
    --query 'SecurityGroups[0].IpPermissions[?contains(IpRanges[].CidrIp, `10.0.0.0/8`)].FromPort' --output text
}
ssh_new=$(sg_ports nr-open-ssh)
rdp_new=$(sg_ports nr-open-rdp)
[ "$ssh_new" = "22" ] || { echo "nr-open-ssh got ports [$ssh_new] from the narrow rule, want only 22" >&2; exit 1; }
[ "$rdp_new" = "3389" ] || { echo "nr-open-rdp got ports [$rdp_new] from the narrow rule, want only 3389" >&2; exit 1; }
echo "ok: each security group got only the port it was flagged for (22 and 3389)"

pp=$(aws iam get-account-password-policy --query 'PasswordPolicy.[MinimumPasswordLength,PasswordReusePrevention]' --output text)
[ "$pp" = "$(printf '14\t24')" ] || { echo "password policy is [$pp], want 14 and 24" >&2; exit 1; }
echo "ok: password policy needs 14 characters and blocks the last 24 passwords"

trail=$(aws cloudtrail describe-trails --query 'trailList[?Name==`nis2-multi-region`].[IsMultiRegionTrail,LogFileValidationEnabled,S3BucketName]' --output text)
[ "$trail" = "$(printf 'True\tTrue\tnr-trail-logs')" ] || { echo "multi-region trail is [$trail]" >&2; exit 1; }
echo "ok: trail nis2-multi-region is multi-region with log file validation"

for vpc in $(aws ec2 describe-vpcs --query 'Vpcs[].VpcId' --output text); do
  fl=$(aws ec2 describe-flow-logs --filter "Name=resource-id,Values=$vpc" --query 'FlowLogs[0].[TrafficType,LogDestination]' --output text)
  [ "$fl" = "$(printf 'ALL\tarn:aws:s3:::nr-flow-logs')" ] || { echo "flow log of $vpc is [$fl]" >&2; exit 1; }
done
echo "ok: every VPC sends flow logs of all traffic to nr-flow-logs"
