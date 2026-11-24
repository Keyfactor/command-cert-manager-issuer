#!/usr/bin/env bash
# Reproduces Keyfactor/command-cert-manager-issuer#93 against a real cluster.
#
# Runs the issuer controller from this checkout on your host, against a mock
# Command that always returns 503, in two modes:
#   fixed - identical error body each time   (control: expect normal backoff)
#   vary  - unique error body each time      (expect a tight retry loop)
#
# Usage: KUBE_CONTEXT=<context> [DURATION=60] ./run.sh
#
# SAFETY: the controller reconciles EVERY Issuer/ClusterIssuer it can see and
# rewrites their status. Use a scratch cluster (e.g. `minikube start -p issuer-probe`).
# The script refuses to run if other issuers exist.
set -euo pipefail

: "${KUBE_CONTEXT:?set KUBE_CONTEXT to the scratch cluster context}"
DURATION="${DURATION:-60}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out/$(date +%Y%m%d-%H%M%S)"
NS=repro93
CI=repro93-probe
CM_VERSION=v1.17.0
kc() { kubectl --context "$KUBE_CONTEXT" "$@"; }
mkdir -p "$OUT"

echo "Context: $KUBE_CONTEXT   Duration per mode: ${DURATION}s   Output: $OUT"

# --- preflight -------------------------------------------------------------
if kc get crd clusterissuers.command-issuer.keyfactor.com >/dev/null 2>&1; then
  others=$( (kc get clusterissuers.command-issuer.keyfactor.com -o name; \
             kc get issuers.command-issuer.keyfactor.com -A -o name) 2>/dev/null \
             | grep -v "/$CI$" || true)
  if [ -n "$others" ]; then
    echo "REFUSING: other command-issuer resources exist; the controller would modify them:" >&2
    echo "$others" >&2
    exit 1
  fi
fi
kc apply -f "$ROOT/config/crd/bases/" >/dev/null
if ! kc get crd certificaterequests.cert-manager.io >/dev/null 2>&1; then
  echo "Installing cert-manager $CM_VERSION CRDs (CRDs only)"
  kc apply --server-side -f "https://github.com/cert-manager/cert-manager/releases/download/$CM_VERSION/cert-manager.crds.yaml" >/dev/null
fi

# --- build -----------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$OUT/key.pem" -out "$OUT/cert.pem" -days 2 \
  -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
(cd "$HERE/mock" && go build -o "$OUT/mock" .)
(cd "$ROOT" && go build -o "$OUT/manager" ./cmd)

# --- fixtures --------------------------------------------------------------
PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done
  kc delete clusterissuer.command-issuer.keyfactor.com "$CI" --ignore-not-found >/dev/null 2>&1 || true
  kc delete ns "$NS" --ignore-not-found >/dev/null 2>&1 || true
}
trap cleanup EXIT
kc create ns "$NS" >/dev/null
kc -n "$NS" create secret generic auth --type=kubernetes.io/basic-auth \
  --from-literal=username=u --from-literal=password=p >/dev/null
kc -n "$NS" create secret generic ca --from-file=ca.crt="$OUT/cert.pem" >/dev/null
kc apply -f - >/dev/null <<YAML
apiVersion: command-issuer.keyfactor.com/v1alpha1
kind: ClusterIssuer
metadata:
  name: $CI
spec:
  hostname: localhost:8443
  apiPath: /KeyfactorAPI
  commandSecretName: auth
  caSecretName: ca
YAML

# --- run one mode ----------------------------------------------------------
run_mode() {
  local mode=$1
  "$OUT/mock" "$mode" "$OUT/cert.pem" "$OUT/key.pem" > "$OUT/mock-$mode.log" 2>&1 & local mp=$!
  sleep 1
  "$OUT/manager" --cluster-resource-namespace="$NS" --metrics-bind-address=0 \
    --health-probe-bind-address=0 > "$OUT/manager-$mode.log" 2>&1 & local cp=$!
  PIDS+=("$mp" "$cp")
  sleep "$DURATION"
  kc get clusterissuers.command-issuer.keyfactor.com "$CI" -o yaml > "$OUT/issuer-$mode.yaml"
  kill "$cp" "$mp" 2>/dev/null || true; wait "$cp" "$mp" 2>/dev/null || true
  # Gap stats from mock timestamps (epoch ms, column 1)
  local n; n=$(wc -l < "$OUT/mock-$mode.log" | tr -d ' ')
  awk 'NR>1{print $1-p} {p=$1}' "$OUT/mock-$mode.log" | sort -n > "$OUT/gaps-$mode.txt"
  awk -v mode="$mode" -v dur="$DURATION" -v n="$n" '{a[NR]=$1} END {
      if (NR==0) { printf "%-6s health checks in %ds: %5d\n", mode, dur, n; exit }
      printf "%-6s health checks in %ds: %5d | gap min/median/max: %d / %d / %d ms\n",
             mode, dur, n, a[1], a[int((NR+1)/2)], a[NR] }' "$OUT/gaps-$mode.txt" | tee -a "$OUT/summary.txt"
  echo "       first 12 gaps (ms): $(awk 'NR>1{printf "%d ",$1-p} {p=$1}' "$OUT/mock-$mode.log" | cut -d' ' -f1-12)" | tee -a "$OUT/summary.txt"
  echo "       'Reconciler error' lines: $(grep -c 'Reconciler error' "$OUT/manager-$mode.log" || true)" | tee -a "$OUT/summary.txt"
}

echo "--- fixed (control) ---"; run_mode fixed
# Reset the issuer status so the second run starts clean
kc patch clusterissuers.command-issuer.keyfactor.com "$CI" --subresource=status --type=merge \
  -p '{"status":{"conditions":[]}}' >/dev/null 2>&1 || true
echo "--- vary ---"; run_mode vary
echo; echo "Done. Evidence in $OUT (summary.txt, mock-*.log, manager-*.log, issuer-*.yaml)"
