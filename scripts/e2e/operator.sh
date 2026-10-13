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

echo "step 3: enable the private endpoint of the EKS cluster (guidance of eks_cluster_private_nodes_enabled)"
if aws eks update-cluster-config --name nr-eks --resources-vpc-config endpointPrivateAccess=true,endpointPublicAccess=false >/tmp/eks-update.log 2>&1; then
  echo "  endpointPrivateAccess=true, endpointPublicAccess=false"
else
  grep -q UnknownOperation /tmp/eks-update.log || { cat /tmp/eks-update.log >&2; exit 1; }
  echo "  emulator does not implement UpdateClusterConfig: recreate the mock cluster with the target settings"
  role=$(aws eks describe-cluster --name nr-eks --query cluster.roleArn --output text)
  subnets=$(aws eks describe-cluster --name nr-eks --query 'cluster.resourcesVpcConfig.subnetIds' --output text | tr '\t' ',')
  aws eks delete-cluster --name nr-eks >/dev/null
  aws eks create-cluster --name nr-eks --role-arn "$role" --resources-vpc-config "subnetIds=$subnets,endpointPublicAccess=false,endpointPrivateAccess=true" >/dev/null
fi
