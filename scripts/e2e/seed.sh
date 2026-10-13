#!/usr/bin/env bash
set -euo pipefail

case "${AWS_ENDPOINT_URL:-}" in
  http://localhost:*|http://127.0.0.1:*|http://*-floci:*) ;;
  *) echo "refusing to run: AWS_ENDPOINT_URL must point to the local emulator" >&2; exit 1 ;;
esac
[ "${AWS_ACCESS_KEY_ID:-}" = "test" ] || { echo "refusing to run: dummy credentials only" >&2; exit 1; }

aws s3api create-bucket --bucket nr-public-acl >/dev/null
aws s3api put-bucket-acl --bucket nr-public-acl --grant-read 'uri="http://acs.amazonaws.com/groups/global/AllUsers"' >/dev/null

aws s3api create-bucket --bucket nr-public-write >/dev/null
aws s3api put-bucket-acl --bucket nr-public-write --grant-write 'uri="http://acs.amazonaws.com/groups/global/AllUsers"' >/dev/null

aws s3api create-bucket --bucket nr-public-policy >/dev/null
aws s3api put-bucket-policy --bucket nr-public-policy --policy '{"Version":"2012-10-17","Statement":[{"Sid":"PublicWrite","Effect":"Allow","Principal":"*","Action":"s3:PutObject","Resource":"arn:aws:s3:::nr-public-policy/*"}]}' >/dev/null

aws s3api create-bucket --bucket nr-plain >/dev/null
aws s3api create-bucket --bucket nr-existing-policy >/dev/null
aws s3api put-bucket-policy --bucket nr-existing-policy --policy '{"Version":"2012-10-17","Statement":[{"Sid":"KeepMe","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::nr-existing-policy/*"}]}' >/dev/null
aws s3api create-bucket --bucket nr-log-target >/dev/null

aws kms create-key --description nr-e2e --query KeyMetadata.Arn --output text > /work/kms_key_arn.txt

vpc=$(aws ec2 create-vpc --cidr-block 10.20.0.0/16 --query Vpc.VpcId --output text)
sub=$(aws ec2 create-subnet --vpc-id "$vpc" --cidr-block 10.20.1.0/24 --availability-zone us-east-1a --query Subnet.SubnetId --output text)
sub2=$(aws ec2 create-subnet --vpc-id "$vpc" --cidr-block 10.20.2.0/24 --availability-zone us-east-1b --query Subnet.SubnetId --output text)

mk_sg() {
  aws ec2 create-security-group --group-name "$1" --description "$1" --vpc-id "$vpc" --query GroupId --output text
}
sg_all=$(mk_sg nr-open-all)
aws ec2 authorize-security-group-ingress --group-id "$sg_all" --ip-permissions 'IpProtocol=-1,IpRanges=[{CidrIp=0.0.0.0/0}]' >/dev/null
sg_ssh=$(mk_sg nr-open-ssh)
aws ec2 authorize-security-group-ingress --group-id "$sg_ssh" --protocol tcp --port 22 --cidr 0.0.0.0/0 >/dev/null
sg_rdp=$(mk_sg nr-open-rdp)
aws ec2 authorize-security-group-ingress --group-id "$sg_rdp" --protocol tcp --port 3389 --cidr 0.0.0.0/0 >/dev/null
sg_smb=$(mk_sg nr-open-smb)
aws ec2 authorize-security-group-ingress --group-id "$sg_smb" --protocol tcp --port 445 --cidr 0.0.0.0/0 >/dev/null
sg_any=$(mk_sg nr-open-any)
aws ec2 authorize-security-group-ingress --group-id "$sg_any" --protocol tcp --port 0-65535 --cidr 0.0.0.0/0 >/dev/null

aws ec2 create-volume --size 1 --availability-zone us-east-1a >/dev/null

role=$(aws iam create-role --role-name nr-eks-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"eks.amazonaws.com"},"Action":"sts:AssumeRole"}]}' --query Role.Arn --output text)
aws s3api get-bucket-policy --bucket nr-existing-policy --query Policy --output text > /work/policy_nr-existing-policy.json

aws eks create-cluster --name nr-eks --role-arn "$role" --resources-vpc-config "subnetIds=$sub,$sub2,endpointPublicAccess=true,endpointPrivateAccess=false" >/dev/null
