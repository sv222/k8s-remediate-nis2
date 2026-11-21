#!/usr/bin/env bash
# End to end test of the Prowler Kubernetes path on a real kind cluster.
#
# It creates a kind cluster, installs Kyverno, deploys pods that break the pod
# security rules, scans the cluster with Prowler, runs the tool on the OCSF
# report, applies the generated policies in Audit mode, checks that the Kyverno
# policy reports list the bad pods, switches the policies to Deny and checks
# that a new bad pod is refused. The cluster is deleted at the end.
#
# Needs docker, kind, kubectl and python3. Prowler runs in a venv under the
# work directory, never global. Set E2E_KEEP=1 to keep the work directory.
set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
WORK=${E2E_WORKDIR:-$ROOT/temp/e2e-k8s}
KEEP=${E2E_KEEP:-0}

PROWLER_VERSION=5.51.0
KYVERNO_VERSION=1.19.1
GO_IMAGE=golang:1.27.2
CLUSTER=${E2E_CLUSTER:-nis2-e2e}

log() { printf '\n==> %s\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is required"
command -v kind >/dev/null || die "kind is required"
command -v kubectl >/dev/null || die "kubectl is required"
command -v python3 >/dev/null || die "python3 is required"
docker info >/dev/null 2>&1 || die "docker daemon is not reachable"

cleanup() {
  local rc=$?
  set +e
  log "teardown"
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1
  if [ "$KEEP" != 1 ]; then rm -rf "$WORK"; else echo "kept $WORK"; fi
  exit $rc
}
trap cleanup EXIT

rm -rf "$WORK"
mkdir -p "$WORK/bin"

log "build the CLI in $GO_IMAGE"
docker run --rm --cpus 2 -v "$ROOT:/src:ro" -v "$WORK/bin:/out" -w /src \
  -e CGO_ENABLED=0 -e GOFLAGS=-buildvcs=false "$GO_IMAGE" \
  sh -c "go build -trimpath -o /out/k8s-remediate-nis2 ./cmd/k8s-remediate-nis2"

log "create the kind cluster $CLUSTER"
kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
kind create cluster --name "$CLUSTER" --wait 180s

log "install Kyverno $KYVERNO_VERSION"
kubectl create -f "https://github.com/kyverno/kyverno/releases/download/v$KYVERNO_VERSION/install.yaml"
kubectl -n kyverno wait --for=condition=Available deploy --all --timeout=300s

log "deploy the bad pods"
cat > "$WORK/badpods.yaml" <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: nis2demo
---
apiVersion: v1
kind: Pod
metadata:
  name: bad-privileged
  namespace: nis2demo
spec:
  containers:
    - name: c
      image: nginx:alpine
      securityContext:
        privileged: true
---
apiVersion: v1
kind: Pod
metadata:
  name: bad-hostpid
  namespace: nis2demo
spec:
  hostPID: true
  containers:
    - name: c
      image: nginx:alpine
---
apiVersion: v1
kind: Pod
metadata:
  name: bad-hostipc
  namespace: nis2demo
spec:
  hostIPC: true
  containers:
    - name: c
      image: nginx:alpine
---
apiVersion: v1
kind: Pod
metadata:
  name: bad-hostnet
  namespace: nis2demo
spec:
  hostNetwork: true
  containers:
    - name: c
      image: nginx:alpine
---
apiVersion: v1
kind: Pod
metadata:
  name: bad-root
  namespace: nis2demo
spec:
  containers:
    - name: c
      image: nginx:alpine
      securityContext:
        runAsUser: 0
---
apiVersion: v1
kind: Pod
metadata:
  name: bad-privesc
  namespace: nis2demo
spec:
  containers:
    - name: c
      image: nginx:alpine
      securityContext:
        allowPrivilegeEscalation: true
---
apiVersion: v1
kind: Pod
metadata:
  name: bad-hostpath
  namespace: nis2demo
spec:
  containers:
    - name: c
      image: nginx:alpine
      volumeMounts:
        - name: h
          mountPath: /host
          readOnly: true
  volumes:
    - name: h
      hostPath:
        path: /var/log
        type: Directory
EOF
kubectl apply -f "$WORK/badpods.yaml"
kubectl -n nis2demo wait --for=condition=Ready pods --all --timeout=240s

log "run Prowler $PROWLER_VERSION in a venv"
python3 -m venv "$WORK/venv"
"$WORK/venv/bin/pip" install -q "prowler-cloud==$PROWLER_VERSION"
set +e
"$WORK/venv/bin/prowler" kubernetes --no-banner -M json-ocsf -o "$WORK/scan" --output-filename scan >"$WORK/scan.log" 2>&1
rc=$?
set -e
[ "$rc" = 0 ] || [ "$rc" = 3 ] || { tail -20 "$WORK/scan.log" >&2; die "prowler failed with exit code $rc"; }
[ -s "$WORK/scan/scan.ocsf.json" ] || die "prowler wrote no OCSF report"
grep -E "Failed|Passed" "$WORK/scan.log" | sed 's/\x1b\[[0-9;]*m//g' | head -1

log "remediate the OCSF report"
"$WORK/bin/k8s-remediate-nis2" remediate --prowler "$WORK/scan/scan.ocsf.json" --out "$WORK/rem"
ls "$WORK/rem/kyverno" | sed 's/^/  /'

log "apply the generated policies in Audit mode"
kubectl apply -f "$WORK/rem/kyverno/"

log "check that the policy reports list the bad pods"
python3 - "$WORK" <<'PY'
import json, subprocess, sys, time

bad = ["bad-privileged", "bad-hostpid", "bad-hostipc", "bad-hostnet", "bad-root", "bad-privesc", "bad-hostpath"]
found = set()
deadline = time.time() + 300
while time.time() < deadline and len(found) < len(bad):
    data = subprocess.run(
        ["kubectl", "get", "policyreports.wgpolicyk8s.io,clusterpolicyreports.wgpolicyk8s.io", "-A", "-o", "json"],
        capture_output=True, text=True)
    if data.returncode == 0:
        doc = json.loads(data.stdout or "{}")
        for item in doc.get("items", []):
            scope = (item.get("scope") or {}).get("name", "")
            for result in item.get("results", []):
                if not str(result.get("policy", "")).startswith("nis2-") or result.get("result") != "fail":
                    continue
                names = json.dumps(result.get("subjects", [])) + json.dumps(result.get("resources", [])) + " " + scope
                for pod in bad:
                    if pod not in found and pod in names:
                        found.add(pod)
    time.sleep(10)
missing = sorted(set(bad) - found)
if missing:
    sys.exit("policy reports do not list the failing pods: " + ", ".join(missing))
print("policy reports list all %d bad pods" % len(bad))
PY

log "switch the policies to Deny and check a new bad pod is refused"
mkdir -p "$WORK/enforce"
for f in "$WORK"/rem/kyverno/*.yaml; do
  sed 's/validationActions: \[Audit\]/validationActions: [Deny]/' "$f" > "$WORK/enforce/$(basename "$f")"
done
kubectl apply -f "$WORK/enforce/"

cat > "$WORK/bad-extra.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: bad-privileged-extra
  namespace: nis2demo
spec:
  containers:
    - name: c
      image: nginx:alpine
      securityContext:
        privileged: true
EOF
cat > "$WORK/good-pod.yaml" <<'EOF'
apiVersion: v1
kind: Pod
metadata:
  name: good-pod
  namespace: nis2demo
spec:
  containers:
    - name: c
      image: nginx:alpine
      securityContext:
        runAsNonRoot: true
        runAsUser: 101
        allowPrivilegeEscalation: false
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop: [ALL]
        readOnlyRootFilesystem: true
EOF

if kubectl apply --dry-run=server -f "$WORK/bad-extra.yaml" >/dev/null 2>&1; then
  die "a new privileged pod was admitted while the policies are in Deny mode"
fi
echo "new privileged pod refused, as expected"
kubectl apply -f "$WORK/good-pod.yaml" >/dev/null
echo "good pod admitted, as expected"
kubectl -n nis2demo delete pod good-pod --ignore-not-found >/dev/null

log "done"
