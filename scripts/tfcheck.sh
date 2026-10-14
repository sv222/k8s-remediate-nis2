#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
SCRIPTS=$ROOT/scripts/e2e
PREFIX=${TFCHECK_PREFIX:-nrval}
WORK=${TFCHECK_WORKDIR:-$ROOT/temp/tfcheck}
TERRAFORM_IMAGE=hashicorp/terraform:1.16.5
GO_IMAGE=golang:1.27.2
GOVOL=$PREFIX-tfcheck-gomod
UIDGID="$(id -u):$(id -g)"
DOCKER_RESOURCES=${TFCHECK_DOCKER_FLAGS:---cpus 2}

log() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is required"
docker info >/dev/null 2>&1 || die "docker daemon is not reachable"

cleanup() {
  local rc=$?
  set +e
  docker volume rm "$GOVOL" >/dev/null 2>&1
  if [ "${TFCHECK_KEEP:-0}" != 1 ]; then rm -rf "$WORK"; fi
  exit $rc
}
trap cleanup EXIT

rm -rf "$WORK"
mkdir -p "$WORK"/{bin,plugins,corpus,out}
chmod 777 "$WORK" "$WORK"/{bin,plugins,corpus,out}

gorun() {
  # shellcheck disable=SC2086
  docker run --rm $DOCKER_RESOURCES -v "$ROOT:/src:ro" -v "$WORK:/work" -v "$GOVOL:/go" -w /src \
    -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false -e GOCACHE=/go/cache -e TFCHECK_DIR=/work/corpus \
    "$GO_IMAGE" sh -c "($*); rc=\$?; chown -R $UIDGID /work; exit \$rc"
}

tf() {
  # shellcheck disable=SC2086
  docker run --rm $DOCKER_RESOURCES --user "$UIDGID" -v "$WORK/tf:/tf" -w /tf -v "$WORK/plugins:/plugins" \
    -e TF_PLUGIN_CACHE_DIR=/plugins -e TF_IN_AUTOMATION=1 -e TF_INPUT=0 -e HOME=/tmp "$TERRAFORM_IMAGE" "$@"
}

log "build the CLI and write the generated files"
gorun "go build -trimpath -o /work/bin/k8s-remediate-nis2 ./cmd/k8s-remediate-nis2 \
  && go test ./internal/render -run TestPropertyTerraformCheckCorpus -count=1 \
  && cd /src/cmd/testdata \
  && for pair in 'legacy_and_bench:--prowler prowler_legacy.json --kube-bench kube_bench.json' 'ocsf_only:--prowler prowler_ocsf.json' 'aws_gaps:--prowler prowler_aws_gaps.json'; do \
       name=\${pair%%:*}; args=\${pair#*:}; /work/bin/k8s-remediate-nis2 remediate \$args --out /work/out/\$name; \
     done"

dirs=()
for d in "$WORK"/out/*/terraform "$WORK"/corpus/terraform; do
  [ -d "$d" ] && dirs+=("$d")
done
[ "${#dirs[@]}" -ge 2 ] || die "no generated Terraform to check"

n=0
for d in "${dirs[@]}"; do
  n=$((n + 1))
  name=$(basename "$(dirname "$d")")
  log "terraform fmt -check and validate: $name"
  rm -rf "$WORK/tf"
  mkdir -p "$WORK/tf"
  chmod 777 "$WORK/tf"
  cp "$d"/*.tf "$WORK/tf/"
  cp "$SCRIPTS/provider.tf" "$SCRIPTS/pin_override.tf" "$WORK/tf/"
  chmod -R a+rwX "$WORK/tf"
  tf fmt -check -diff -no-color
  tf init -backend=false -no-color >/dev/null
  tf validate -no-color
done
echo
echo "terraform fmt -check and validate passed for $n generated sets"
