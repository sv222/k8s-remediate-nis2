#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPTS=$ROOT/scripts/e2e

PREFIX=${E2E_PREFIX:-nrval}
WORK=${E2E_WORKDIR:-$ROOT/temp/e2e}
KEEP=${E2E_KEEP:-0}

FLOCI_IMAGE=floci/floci:2.2.0
PROWLER_IMAGE=toniblyx/prowler@sha256:1e5795706f6c2aedf5c2d404c73af6d3c0bc7a1db8add8d290bd5b41e8ef8425
TERRAFORM_IMAGE=hashicorp/terraform:1.16.5
AWSCLI_IMAGE=amazon/aws-cli:2.38.0
GO_IMAGE=golang:1.27.2

NET=$PREFIX-net
EMU=$PREFIX-floci
GOVOL=$PREFIX-gomod
ENDPOINT=http://$EMU:4566
NOT_SEEDABLE=${E2E_NOT_SEEDABLE:-ec2_securitygroup_allow_ingress_from_internet_to_any_port}
EKS_NOTE="the emulator has no UpdateClusterConfig, so the mock cluster was recreated with the target settings"

UIDGID="$(id -u):$(id -g)"
NET_CREATED=0

log() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is required"
command -v python3 >/dev/null || die "python3 is required"
docker info >/dev/null 2>&1 || die "docker daemon is not reachable"

cleanup() {
  local rc=$?
  set +e
  log "teardown"
  docker rm -f "$EMU" >/dev/null 2>&1
  if [ "$NET_CREATED" = 1 ]; then docker network rm "$NET" >/dev/null 2>&1; fi
  docker volume rm "$GOVOL" >/dev/null 2>&1
  if [ "$KEEP" != 1 ]; then rm -rf "$WORK"; else echo "kept $WORK"; fi
  exit $rc
}
trap cleanup EXIT

envs=(-e "AWS_ENDPOINT_URL=$ENDPOINT" -e AWS_ACCESS_KEY_ID=test -e AWS_SECRET_ACCESS_KEY=test -e AWS_DEFAULT_REGION=us-east-1 -e AWS_PAGER= -e HOME=/tmp)

awscli() {
  docker run --rm --cpus 2 --network "$NET" --user "$UIDGID" -v "$WORK/shared:/work" -v "$SCRIPTS:/scripts:ro" "${envs[@]}" --entrypoint bash "$AWSCLI_IMAGE" "$@"
}

prowler_scan() {
  local name=$1
  local rc=0
  docker run --rm --network "$NET" --user "$UIDGID" --cpus 2 --memory 2g -v "$WORK/scans:/scans" "${envs[@]}" "$PROWLER_IMAGE" \
    aws -f us-east-1 --scan-unused-services -M json-ocsf -o "/scans/$name" --output-filename scan --no-banner \
    --check $(tr '\n' ' ' < "$SCRIPTS/checks.txt") >"$WORK/scans/$name.log" 2>&1 || rc=$?
  [ "$rc" = 0 ] || [ "$rc" = 3 ] || { tail -30 "$WORK/scans/$name.log" >&2; die "prowler failed with exit code $rc"; }
  [ -s "$WORK/scans/$name/scan.ocsf.json" ] || die "prowler wrote no OCSF report for $name"
  grep -E "Failed|Passed" "$WORK/scans/$name.log" | sed 's/\x1b\[[0-9;]*m//g' | head -1
}

terraform_run() {
  docker run --rm --cpus 2 --network "$NET" --user "$UIDGID" -v "$WORK/tf:/tf" -w /tf -v "$WORK/plugins:/plugins" \
    -e TF_PLUGIN_CACHE_DIR=/plugins -e TF_IN_AUTOMATION=1 -e TF_INPUT=0 "${envs[@]}" "$TERRAFORM_IMAGE" "$@"
}

rm -rf "$WORK"
mkdir -p "$WORK"/{bin,shared,scans,plugins,tf}
chmod 777 "$WORK" "$WORK"/{bin,shared,scans,plugins,tf}

log "build the CLI in $GO_IMAGE"
docker run --rm --cpus 2 -v "$ROOT:/src:ro" -v "$WORK/bin:/out" -v "$GOVOL:/go" -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false -e GOCACHE=/go/cache \
  "$GO_IMAGE" sh -c "go build -trimpath -o /out/k8s-remediate-nis2 ./cmd/k8s-remediate-nis2 && chown $UIDGID /out/k8s-remediate-nis2"

log "start the emulator $FLOCI_IMAGE"
if ! docker network inspect "$NET" >/dev/null 2>&1; then
  docker network create "$NET" >/dev/null
  NET_CREATED=1
fi
docker rm -f "$EMU" >/dev/null 2>&1 || true
docker run -d --name "$EMU" --network "$NET" --memory 1g --cpus 2 \
  -e FLOCI_SERVICES_EKS_MOCK=true -e FLOCI_SERVICES_EC2_MOCK=true -e "FLOCI_HOSTNAME=$EMU" "$FLOCI_IMAGE" >/dev/null
for _ in $(seq 60); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$EMU")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$EMU")" = healthy ] || die "emulator did not become healthy"

log "seed bad resources"
awscli /scripts/seed.sh

log "prowler scan: before"
prowler_scan before

log "remediate"
"$WORK/bin/k8s-remediate-nis2" remediate --prowler "$WORK/scans/before/scan.ocsf.json" --out "$WORK/rem" --export-evidence

log "terraform validate, plan, apply"
cp "$WORK"/rem/terraform/*.tf "$WORK/tf/"
cp "$SCRIPTS/provider.tf" "$WORK/tf/provider.tf"
cp "$SCRIPTS/pin_override.tf" "$WORK/tf/pin_override.tf"
python3 - "$WORK" <<'PY'
import glob, json, re, sys
w = sys.argv[1]

def sg_ids(prefix):
    ids = []
    for p in sorted(glob.glob(w + "/rem/terraform/" + prefix + "__*.tf")):
        ids += re.findall(r'security_group_id = "(sg-[0-9a-f]+)"',open(p, encoding="utf-8").read())
    if not ids:
        sys.exit("no generated rule file for " + prefix)
    return ids

policy = open(w + "/shared/policy_nr-existing-policy.json", encoding="utf-8").read().strip()
kms = open(w + "/shared/kms_key_arn.txt", encoding="utf-8").read().strip()
vars_ = {
    "kms_key_arns": {"us-east-1": kms},
    "ssh_allowed_cidr": {i: "10.0.0.0/8" for i in sg_ids("sg_restrict_ssh")},
    "rdp_allowed_cidr": {i: "10.0.0.0/8" for i in sg_ids("sg_restrict_rdp")},
    "access_log_bucket": "nr-log-target",
    "s3_existing_bucket_policies": {"nr-existing-policy": policy},
}
json.dump(vars_, open(w + "/tf/e2e.auto.tfvars.json", "w"))
PY
chmod -R a+rwX "$WORK/tf"
terraform_run init -no-color
terraform_run validate -no-color
terraform_run plan -no-color -out=tfplan
terraform_run apply -no-color -auto-approve tfplan
set +e
terraform_run plan -no-color -detailed-exitcode >"$WORK/plan2.log" 2>&1
plan2=$?
set -e
echo "second plan exit code: $plan2 (0 = no drift, 2 = drift)"
if [ "$plan2" = 1 ]; then tail -20 "$WORK/plan2.log"; die "second terraform plan failed"; fi

log "check applied state"
awscli /scripts/verify.sh

log "prowler scan: after terraform apply"
prowler_scan after_terraform

log "follow-up steps from the generated guidance"
awscli /scripts/operator.sh

log "prowler scan: after follow-up"
prowler_scan after_followup

log "report"
python3 "$SCRIPTS/report.py" --checks "$SCRIPTS/checks.txt" \
  --before "$WORK/scans/before/scan.ocsf.json" \
  --templates "$WORK/scans/after_terraform/scan.ocsf.json" \
  --final "$WORK/scans/after_followup/scan.ocsf.json" \
  --mapping "$WORK/rem/mapping.md" \
  --not-seedable "$NOT_SEEDABLE" \
  --note "eks_cluster_private_nodes_enabled=$EKS_NOTE" \
  --note "eks_cluster_not_publicly_accessible=$EKS_NOTE" \
  --out "$WORK/report.md"
