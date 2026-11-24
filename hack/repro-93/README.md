# Repro for #93 (excessive healthcheck retries)

A mock Command always returns 503. Two modes:
- `fixed`: identical error body each time (control: expect normal exponential backoff)
- `vary`: unique `CorrelationId` in each body (the bug: tight retry loop, because the `Ready`
  condition message changes, the status update fires a watch event, and the event bypasses the rate limiter)

Use a SCRATCH cluster. The controller reconciles every Issuer/ClusterIssuer it sees; both scripts
refuse to run if other command-issuer resources exist. Needs kubectl, openssl, curl (+ go for run.sh, helm for run-pod.sh).

    minikube start -p issuer-probe

## run-pod.sh: the real controller pod (use this to verify an RC)

Installs the chart from this checkout with the image you choose, runs the mock in-cluster, and reports attempts and gaps.

    # released image
    KUBE_CONTEXT=issuer-probe IMAGE_TAG=2.5.2 DURATION=60 ./hack/repro-93/run-pod.sh

    # release candidate: build/load the image so the cluster can pull it, then
    minikube -p issuer-probe image load local/command-cert-manager-issuer:rc1
    KUBE_CONTEXT=issuer-probe IMAGE_REPO=local/command-cert-manager-issuer IMAGE_TAG=rc1 ./hack/repro-93/run-pod.sh

Pass criteria for a fix: in `vary` mode the gaps must grow (backoff or the configured fixed interval),
matching `fixed`, instead of staying at ~50 ms. `summary.txt` records the image digest tested.
Set KEEP=1 to leave the namespace/release for inspection.

## run.sh: controller built from this checkout, run on the host

Faster iteration (no image build): builds `./cmd` and runs it as a local process against the cluster
with a host-side mock on :8443. Not the pod, so use run-pod.sh for final evidence.

    KUBE_CONTEXT=issuer-probe DURATION=60 ./hack/repro-93/run.sh

Output goes to `out/<timestamp>/` (gitignored).

## Reference result (released image, 45 s per mode)

    fixed  14 health checks   gaps: 6 6 28 46 90 172 332 652 1293 2570 5135 10257 ms
    vary  935 health checks   gaps: 8 7 8 6 5 7 5 6 5 8 4 6 ms   (median 50 ms)
