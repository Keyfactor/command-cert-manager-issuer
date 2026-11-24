#!/usr/bin/env bash
# Reproduces Keyfactor/command-cert-manager-issuer#93 against the real controller POD.
#
# Installs the chart in this checkout with a container image of your choice, plus an
# in-cluster mock Command that always returns 503, then measures how often the
# controller health-checks it:
#   fixed - identical error body each time   (control: expect normal backoff)
#   vary  - unique error body each time      (the bug: tight retry loop)
#
# Usage:
#   KUBE_CONTEXT=<ctx> IMAGE_TAG=2.5.2 ./run-pod.sh                      # released image
#   KUBE_CONTEXT=<ctx> IMAGE_REPO=local/issuer IMAGE_TAG=rc1 ./run-pod.sh  # your RC build
#       (an RC must already be pullable by the cluster, e.g. `minikube -p <p> image load`)
#
# Env: DURATION (default 60s per mode), NS (default repro93-pod), IMAGE_REPO
#      (default keyfactor/command-cert-manager-issuer), KEEP=1 to skip cleanup.
#
# SAFETY: the controller reconciles EVERY Issuer/ClusterIssuer in the cluster and
# rewrites their status. Use a scratch cluster. The script refuses if others exist.
set -euo pipefail

: "${KUBE_CONTEXT:?set KUBE_CONTEXT to the scratch cluster context}"
: "${IMAGE_TAG:?set IMAGE_TAG, e.g. 2.5.2 (the chart default tag is not the app version)}"
IMAGE_REPO="${IMAGE_REPO:-keyfactor/command-cert-manager-issuer}"
DURATION="${DURATION:-60}"
NS="${NS:-repro93-pod}"
REL=cmd-issuer
CI=repro93-probe
CM_VERSION=v1.17.0
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
CHART="$ROOT/deploy/charts/command-cert-manager-issuer"
OUT="$HERE/out/pod-$(date +%Y%m%d-%H%M%S)"
kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }
mkdir -p "$OUT"
echo "Context: $KUBE_CONTEXT  Image: $IMAGE_REPO:$IMAGE_TAG  Duration/mode: ${DURATION}s  Output: $OUT"

# --- preflight -------------------------------------------------------------
if kc get crd clusterissuers.command-issuer.keyfactor.com >/dev/null 2>&1; then
  others=$( (kc get clusterissuers.command-issuer.keyfactor.com -o name; \
             kc get issuers.command-issuer.keyfactor.com -A -o name) 2>/dev/null \
             | grep -v "/$CI$" || true)
  if [ -n "$others" ]; then
    echo "REFUSING: other command-issuer resources exist; the controller would modify them:" >&2
    echo "$others" >&2; exit 1
  fi
  CRD_CREATE=false   # CRDs already present (not owned by this release); leave them alone
else
  CRD_CREATE=true    # chart installs them and removes them on uninstall
fi
if ! kc get crd certificaterequests.cert-manager.io >/dev/null 2>&1; then
  echo "Installing cert-manager $CM_VERSION CRDs (CRDs only)"
  kc apply --server-side -f "https://github.com/cert-manager/cert-manager/releases/download/$CM_VERSION/cert-manager.crds.yaml" >/dev/null
fi

cleanup() {
  [ "${KEEP:-}" = 1 ] && { echo "KEEP=1: leaving namespace $NS and release $REL"; return; }
  kc delete clusterissuer.command-issuer.keyfactor.com "$CI" --ignore-not-found >/dev/null 2>&1 || true
  helm --kube-context "$KUBE_CONTEXT" -n "$NS" uninstall "$REL" >/dev/null 2>&1 || true
  kc delete ns "$NS" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT

# --- mock Command (in-cluster) --------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 2 \
  -subj "/CN=mock" -addext "subjectAltName=DNS:mock-fixed.$NS.svc,DNS:mock-vary.$NS.svc" 2>/dev/null
cat > "$OUT/mock.py" <<'PY'
import http.server, os, ssl, time, itertools
MODE = os.environ["MODE"]; n = itertools.count(1)
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        i = next(n); now = time.time_ns()
        print(f"{now // 1_000_000} {i} {self.command} {self.path}", flush=True)
        body = (f'{{"Message":"upstream unavailable","CorrelationId":"req-{i}-{now}"}}'
                if MODE == "vary" else "no healthy upstream").encode()
        self.send_response(503); self.send_header("Content-Length", str(len(body))); self.end_headers()
        self.wfile.write(body)
    do_POST = do_PUT = do_GET
    def log_message(self, *a): pass
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
s = http.server.ThreadingHTTPServer(("", 8443), H); s.socket = ctx.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY
kc create ns "$NS" >/dev/null
kc -n "$NS" create secret tls mock-tls --cert="$OUT/cert.pem" --key="$OUT/key.pem" >/dev/null
kc -n "$NS" create configmap mock-src --from-file=mock.py="$OUT/mock.py" >/dev/null
for mode in fixed vary; do
kc -n "$NS" apply -f - >/dev/null <<YAML
apiVersion: apps/v1
kind: Deployment
metadata: {name: mock-$mode}
spec:
  replicas: 1
  selector: {matchLabels: {app: mock-$mode}}
  template:
    metadata: {labels: {app: mock-$mode}}
    spec:
      containers:
      - name: mock
        image: python:3.12-alpine
        command: [python, -u, /src/mock.py]
        env: [{name: MODE, value: $mode}]
        volumeMounts: [{name: src, mountPath: /src}, {name: tls, mountPath: /tls}]
      volumes:
      - {name: src, configMap: {name: mock-src}}
      - {name: tls, secret: {secretName: mock-tls}}
---
apiVersion: v1
kind: Service
metadata: {name: mock-$mode}
spec: {selector: {app: mock-$mode}, ports: [{port: 8443, targetPort: 8443}]}
YAML
done

# --- controller (Helm chart, real image) -----------------------------------
helm --kube-context "$KUBE_CONTEXT" -n "$NS" install "$REL" "$CHART" \
  --set image.repository="$IMAGE_REPO" --set image.tag="$IMAGE_TAG" \
  --set crd.create="$CRD_CREATE" >/dev/null
kc -n "$NS" rollout status deploy -l app.kubernetes.io/instance="$REL" --timeout=180s
kc -n "$NS" rollout status deploy/mock-fixed deploy/mock-vary --timeout=180s
POD=$(kc -n "$NS" get pod -l app.kubernetes.io/instance="$REL" -o jsonpath='{.items[0].metadata.name}')
kc -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].image}{"\n"}{.status.containerStatuses[0].imageID}{"\n"}' \
  | tee "$OUT/image.txt"
kc -n "$NS" create secret generic auth --type=kubernetes.io/basic-auth \
  --from-literal=username=u --from-literal=password=p >/dev/null
kc -n "$NS" create secret generic ca --from-file=ca.crt="$OUT/cert.pem" >/dev/null

# --- measure ---------------------------------------------------------------
run_mode() {
  local mode=$1
  kc apply -f - >/dev/null <<YAML
apiVersion: command-issuer.keyfactor.com/v1alpha1
kind: ClusterIssuer
metadata: {name: $CI}
spec:
  hostname: mock-$mode.$NS.svc:8443
  apiPath: /KeyfactorAPI
  commandSecretName: auth
  caSecretName: ca
YAML
  local t0; t0=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  sleep "$DURATION"
  kc get clusterissuers.command-issuer.keyfactor.com "$CI" -o yaml > "$OUT/issuer-$mode.yaml"
  kc -n "$NS" logs deploy/mock-$mode > "$OUT/mock-$mode.log"
  kc -n "$NS" logs "$POD" --since-time="$t0" > "$OUT/controller-$mode.log"
  kc delete clusterissuer.command-issuer.keyfactor.com "$CI" --wait >/dev/null
  local n; n=$(wc -l < "$OUT/mock-$mode.log" | tr -d ' ')
  awk 'NR>1{print $1-p} {p=$1}' "$OUT/mock-$mode.log" | sort -n > "$OUT/gaps-$mode.txt"
  awk -v mode="$mode" -v dur="$DURATION" -v n="$n" '{a[NR]=$1} END {
      if (NR==0) { printf "%-6s health checks in %ds: %5d\n", mode, dur, n; exit }
      printf "%-6s health checks in %ds: %5d | gap min/median/max: %d / %d / %d ms\n",
             mode, dur, n, a[1], a[int((NR+1)/2)], a[NR] }' "$OUT/gaps-$mode.txt" | tee -a "$OUT/summary.txt"
  echo "       first 12 gaps (ms): $(awk 'NR>1{printf "%d ",$1-p} {p=$1}' "$OUT/mock-$mode.log" | cut -d' ' -f1-12)" | tee -a "$OUT/summary.txt"
  echo "       'Reconciler error' lines in pod log: $(grep -c 'Reconciler error' "$OUT/controller-$mode.log" || true)" | tee -a "$OUT/summary.txt"
}
{ echo "image: $(head -1 "$OUT/image.txt")"; echo "imageID: $(sed -n 2p "$OUT/image.txt")"; } > "$OUT/summary.txt"
echo "--- fixed (control) ---"; run_mode fixed
echo "--- vary ---"; run_mode vary
echo; echo "Done. Evidence in $OUT"
