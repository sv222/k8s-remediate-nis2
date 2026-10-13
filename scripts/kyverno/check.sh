#!/usr/bin/env bash
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
image=${KYVERNO_CLI_IMAGE:-ghcr.io/kyverno/kyverno-cli:v1.19.1}
check() {
  local out
  out=$(docker run --rm -v "$root/templates/kyverno:/pol:ro" -v "$here:/res:ro" "$image" apply "/pol/$1" --resource /res/pods.yaml 2>&1 || true)
  if ! grep -q "pass: $2, fail: $3, warn: 0, error: 0, skip: $4" <<<"$out"; then
    echo "FAIL $1: expected pass $2 fail $3 skip $4"
    echo "$out"
    exit 1
  fi
  echo "ok $1 (pass $2, fail $3, skip $4)"
}
check block_privileged.yaml 11 3 2
check block_hostnet.yaml 13 1 2
check require_nonroot.yaml 2 12 2
