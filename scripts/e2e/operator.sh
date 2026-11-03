#!/usr/bin/env bash
set -euo pipefail

case "${AWS_ENDPOINT_URL:-}" in
  http://localhost:*|http://127.0.0.1:*|http://*-floci:*) ;;
  *) echo "refusing to run: AWS_ENDPOINT_URL must point to the local emulator" >&2; exit 1 ;;
esac
[ "${AWS_ACCESS_KEY_ID:-}" = "test" ] || { echo "refusing to run: dummy credentials only" >&2; exit 1; }

echo "step 1: revoke the internet-open security group rules (follow-up of the sg_restrict_ingress template)"
for sg in $(aws ec2 describe-security-groups --filters 'Name=group-name,Values=nr-open-*' --query 'SecurityGroups[].GroupId' --output text); do
  while read -r proto from to; do
    [ -n "$proto" ] || continue
    if [ "$proto" = "-1" ]; then
      perm='IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]'
    else
      perm="IpProtocol=$proto,FromPort=$from,ToPort=$to,IpRanges=[{CidrIp=0.0.0.0/0}]"
    fi
    aws ec2 revoke-security-group-ingress --group-id "$sg" --ip-permissions "$perm" >/dev/null
    echo "  revoked $proto $from-$to from 0.0.0.0/0 on $sg"
  done < <(aws ec2 describe-security-groups --group-ids "$sg" --query 'SecurityGroups[0].IpPermissions[?contains(IpRanges[].CidrIp, `0.0.0.0/0`)].[IpProtocol,FromPort,ToPort]' --output text)
done

echo "step 2: narrow the internet-open network ACL entries (guidance of the ec2_networkacl_* entries)"
for acl in $(aws ec2 describe-network-acls --query 'NetworkAcls[].NetworkAclId' --output text); do
  nums=$(aws ec2 describe-network-acls --network-acl-ids "$acl" --query 'NetworkAcls[0].Entries[?CidrBlock==`0.0.0.0/0` && Egress==`false` && RuleAction==`allow`].RuleNumber' --output text)
  for n in $nums; do
    aws ec2 replace-network-acl-entry --network-acl-id "$acl" --ingress --rule-number "$n" --protocol -1 --cidr-block 10.0.0.0/8 --rule-action allow >/dev/null
    echo "  narrowed rule $n on $acl"
  done
done

kms=$(cat /work/kms_key_arn.txt)
logging='{"clusterLogging":[{"types":["api","audit","authenticator","controllerManager","scheduler"],"enabled":true}]}'

echo "step 3: private endpoint, all control plane logs and secrets encryption for EKS (guidance of the eks_* entries)"
if aws eks update-cluster-config --name nr-eks --resources-vpc-config endpointPrivateAccess=true,endpointPublicAccess=false >/tmp/eks-update.log 2>&1; then
  aws eks update-cluster-config --name nr-eks --logging "$logging" >/dev/null
  aws eks associate-encryption-config --cluster-name nr-eks --encryption-config "[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"$kms\"}}]" >/dev/null
  echo "  endpointPrivateAccess=true, endpointPublicAccess=false, all log types, secrets encrypted with $kms"
else
  grep -q UnknownOperation /tmp/eks-update.log || { cat /tmp/eks-update.log >&2; exit 1; }
  echo "  emulator does not implement UpdateClusterConfig: recreate the mock cluster with the target settings"
  role=$(aws eks describe-cluster --name nr-eks --query cluster.roleArn --output text)
  subnets=$(aws eks describe-cluster --name nr-eks --query 'cluster.resourcesVpcConfig.subnetIds' --output text | tr '\t' ',')
  aws eks delete-cluster --name nr-eks >/dev/null
  aws eks create-cluster --name nr-eks --role-arn "$role" --resources-vpc-config "subnetIds=$subnets,endpointPublicAccess=false,endpointPrivateAccess=true" \
    --logging "$logging" --encryption-config "[{\"resources\":[\"secrets\"],\"provider\":{\"keyArn\":\"$kms\"}}]" >/dev/null
fi

echo "step 4: log file validation and KMS encryption for the existing trail (guidance of the cloudtrail_* entries)"
aws cloudtrail update-trail --name nr-trail --enable-log-file-validation >/dev/null
for t in $(aws cloudtrail describe-trails --query 'trailList[].Name' --output text); do
  aws cloudtrail update-trail --name "$t" --kms-key-id "$kms" >/dev/null
  echo "  $t: KMS key $kms"
done

echo "step 5: turn on rotation of the customer managed keys (guidance of kms_cmk_rotation_enabled)"
for k in $(aws kms list-keys --query 'Keys[].KeyId' --output text); do
  [ "$(aws kms describe-key --key-id "$k" --query KeyMetadata.KeyManager --output text)" = CUSTOMER ] || continue
  aws kms enable-key-rotation --key-id "$k"
  echo "  rotation on for $k"
done

echo "step 6: move the database to an encrypted copy (guidance of rds_instance_storage_encrypted)"
aws rds create-db-snapshot --db-instance-identifier nr-db --db-snapshot-identifier nr-db-snap >/dev/null
aws rds copy-db-snapshot --source-db-snapshot-identifier nr-db-snap --target-db-snapshot-identifier nr-db-snap-encrypted --kms-key-id "$kms" >/dev/null
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier nr-db-encrypted --db-snapshot-identifier nr-db-snap-encrypted >/dev/null
aws rds delete-db-instance --db-instance-identifier nr-db --skip-final-snapshot >/dev/null
echo "  nr-db replaced by nr-db-encrypted"

echo "step 7: remove the rules of the default security groups (guidance of ec2_securitygroup_default_restrict_traffic)"
for sg in $(aws ec2 describe-security-groups --filters Name=group-name,Values=default --query 'SecurityGroups[].GroupId' --output text); do
  for dir in ingress egress; do
    perms=$(aws ec2 describe-security-groups --group-ids "$sg" --query "SecurityGroups[0].$([ $dir = ingress ] && echo IpPermissions || echo IpPermissionsEgress)" --output json)
    [ "$perms" = "[]" ] || aws ec2 "revoke-security-group-$dir" --group-id "$sg" --ip-permissions "$perms" >/dev/null
  done
  echo "  $sg has no rules"
done
