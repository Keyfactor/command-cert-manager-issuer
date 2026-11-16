# End-to-End Tests

This directory holds two end-to-end suites for command-cert-manager-issuer:

1. [**The Go e2e suite**](#go-e2e-suite) (current). Split into a setup tool that prepares a cluster and a Go test suite that runs against it.
2. [**The legacy Bash suite**](#legacy-bash-e2e-suite-deprecated) (`run_tests.sh`), which will be deprecated once the Go suite reaches parity.

---

# Go e2e suite

The suite has two independent parts:

| Part | Responsibility | Where |
|------|----------------|-------|
| **Setup tool** | Prepares a cluster: cert-manager, the issuer deployment, and the Secrets the issuer needs. | `cmd/setup` |
| **Test suite** | Runs the tests. It assumes the cluster is already prepared and does not deploy anything. | `tests` |

Both parts live in their own Go module (`e2e/go.mod`), separate from the issuer's, so their dependencies never leak into the issuer build. They share the names and defaults in `internal/e2econfig` and the env file loader in `internal/envfile` (namespace, release name, Secret names), so the setup tool and the tests always agree on where things are.

The setup tool never creates `Issuer` or `ClusterIssuer` resources. The test suite owns those.

## Requirements

**Local tools** (the setup tool shells out to these, so it works the same on macOS, Linux and Windows):
- Go (see `go.mod`)
- `kubectl`
- `helm` (v3)
- `docker` — only when deploying a local build of the issuer image
- `minikube` or `kind` — only when deploying a local image to a cluster of that type

**Kubernetes cluster:** any cluster you can reach with a kubeconfig context. You bring your own; the tool does not create one.

**Command instance:** a Keyfactor Command instance configured as described in the [root README](../README.md#configuring-command), and an OAuth client that can enroll certificates.

## What `setup` does

Running `setup` performs these steps, in this order. Nothing is changed until you confirm the cluster in step 2.

1. **Validates inputs.** Checks that the required credentials are set and that the tools it needs are on your `PATH`, and works out how a local image would reach the cluster. It fails here, before touching anything, if it can't.
2. **Asks you to confirm the target.** Prints the kubeconfig context, the cluster's API server URL, and every input (credential values are never printed; secrets are shown only as `set` / `not set`). You must **type the context name** to continue. Without a terminal (for example in CI), it refuses unless you pass `--yes`.
3. **Checks the cluster is reachable.**
4. **Ensures cert-manager is installed.** If a `cert-manager` Helm release exists in the `cert-manager` namespace, or the cert-manager CRDs exist, it is left untouched. Otherwise it is installed from the Jetstack chart (`--cert-manager-version`).
5. **Ensures the namespace exists** (`command-issuer-system` by default).
6. **Creates the Secrets** in that namespace, applied idempotently, so re-running updates them:
   - the **auth Secret** (`auth-secret`) with the OAuth credentials the issuer uses to talk to Command. Credentials are sent to `kubectl` over stdin and never appear in command lines or logs.
   - the **CA trust Secret** (`ca-trust-secret`), only if there are certificate files in `e2e/certs` (or `--ca-certs-dir`). Put the CA certificates for your Command instance there if it uses a private CA. They are bundled into the `ca.crt` key.
7. **Deploys the issuer** (see [Deployment modes](#deployment-modes)) with `helm upgrade --install`, so re-running is safe, then waits for the Deployment to roll out. The Deployment is named after the Helm release.

Every `kubectl` and `helm` call is made with an explicit `--context`, so nothing depends on or changes your kubeconfig's current context.

`setup` does **not**: create a cluster, create Issuer/ClusterIssuer resources, modify an existing cert-manager installation, or write anything outside the cluster (other than a local Docker image build when deploying a local build).

## What `teardown` does

After the same context confirmation, it uninstalls the Helm release and deletes the auth and CA trust Secrets. It leaves cert-manager and the namespace in place, since it can't know whether it was the one to install them.

## Configuration

### Command credentials (required for `setup`)

These are read from environment variables only, never from flags, so they can't leak into shell history or process listings.

| Variable | Required | Description |
|----------|----------|-------------|
| `E2E_OAUTH_TOKEN_URL` | yes | OAuth token endpoint URL |
| `E2E_OAUTH_CLIENT_ID` | yes | OAuth client ID |
| `E2E_OAUTH_CLIENT_SECRET` | yes | OAuth client secret |
| `E2E_OAUTH_AUDIENCE` | no | OAuth audience |
| `E2E_OAUTH_SCOPES` | no | OAuth scopes |

Either export them yourself, or put them in a file. `e2e/e2e.env` is loaded automatically if it exists (use `--env-file` for another path). The same file configures the tests, so you only maintain one:

```bash
cp e2e.env.example e2e.env   # e2e.env is gitignored
# edit e2e.env
```

The file takes `KEY=VALUE` lines (a leading `export ` is accepted). Variables already set in your shell are not overridden by the file.

### Shared settings (optional)

The test suite reads these too, so set them the same way for both.

| Variable | Flag | Default |
|----------|------|---------|
| `E2E_NAMESPACE` | `--namespace` | `command-issuer-system` |
| `E2E_RELEASE_NAME` | `--release-name` | `command-cert-manager-issuer` |
| `E2E_AUTH_SECRET_NAME` | `--auth-secret-name` | `auth-secret` |
| `E2E_CA_SECRET_NAME` | `--ca-secret-name` | `ca-trust-secret` |

Flags take priority over environment variables, which take priority over defaults.

> The Secrets are created in the issuer's own namespace because, with the chart's default settings (`secretConfig.useClusterRoleForSecretAccess: false`), that is the only place the issuer looks for them.

### Flags

Run `go run ./cmd/setup setup -h` for the full list. The most useful:

| Flag | Default | Description |
|------|---------|-------------|
| `--context` | current context | kubeconfig context to deploy to |
| `--yes` | `false` | Skip the confirmation. Required without a terminal. |
| `--chart-version` | `local` | `local` for the chart in this repository, or a published chart version |
| `--image-tag` | `local` | `local` to build the image from this repository, or a published tag |
| `--image-repository` | `keyfactor/command-cert-manager-issuer` | Image repository |
| `--push` | `false` | Push a local build to `--image-repository` instead of loading it into the cluster |
| `--cert-manager-version` | `v1.17.0` | Version installed only if cert-manager is absent |
| `--ca-certs-dir` | `e2e/certs` | Directory of CA certificates to trust |
| `--env-file` | | File of `KEY=VALUE` lines to load |

## Deployment modes

| Mode | Flags | Behavior |
|------|-------|----------|
| **Local build** (default) | _(none)_ | Builds the image from this repository, gets it onto the cluster, and installs the local chart from `deploy/charts`. |
| **Published release** | `--chart-version 2.5.0 --image-tag 2.5.0` | Installs a released chart and image from the public repositories. Pre-release versions (such as `2.6.0-rc1`) are supported. |
| **Mixed** | e.g. `--chart-version local --image-tag 2.5.0` | The local chart with a published image, or the reverse. |

### How a local image reaches the cluster

The tool picks a method from the kubeconfig context name:

| Context | Method |
|---------|--------|
| `minikube` | `minikube image load` |
| `kind-<name>` | `kind load docker-image` |
| `docker-desktop` | Uses the local Docker daemon directly |
| anything else | Not supported automatically. The tool stops before changing anything and asks you to use `--push` or a published tag. |

For other clusters, push to a registry the cluster can pull from. `--image-repository` must be set explicitly with `--push`, so a local build can't be pushed to the default public repository by accident:

```bash
go run ./cmd/setup setup --push --image-repository registry.example.com/me/command-cert-manager-issuer
```

A local build always restarts the Deployment, so you get your latest code even though the tag is still `local`.

## Running the setup

From the `e2e` directory:

```bash
# Local build to a kind or minikube cluster, confirming the context interactively
go run ./cmd/setup --env-file e2e.env --context kind-e2e

# A published release
go run ./cmd/setup --env-file e2e.env --chart-version 2.5.0 --image-tag 2.5.0

# Non-interactive (CI)
go run ./cmd/setup --env-file e2e.env --context kind-e2e --yes

# Remove what setup deployed
go run ./cmd/setup teardown --context kind-e2e
```

Or from the repository root, with `make` (arguments go in `E2E_SETUP_ARGS`; `--env-file` paths are relative to `e2e/`):

```bash
make e2e-setup E2E_SETUP_ARGS="--env-file e2e.env --context kind-e2e"
make e2e-teardown E2E_SETUP_ARGS="--context kind-e2e"
```

`setup` can be re-run at any time to update the Secrets or redeploy.

## Running the tests

The tests assume `setup` has already prepared the cluster. They never install or deploy anything.

```bash
make e2e                              # from the repository root
make e2e E2E_KUBE_CONTEXT=kind-e2e    # against a specific context

# or directly
cd e2e && go test -tags e2e ./tests/... -v -count=1 -timeout 15m
```

The suite is kept apart from the unit tests in three ways: it is its own Go module, its files carry the `e2e` build tag, and `make test` does not run it. Use the same `--context` for `setup` and `E2E_KUBE_CONTEXT` for the tests so both target the same cluster. The tests print the context and API server they use before doing anything.

### Test configuration

The tests read `e2e.env` (or the file named by `E2E_ENV_FILE`) like setup does. In addition to the shared settings above, they need to know which Command instance the test Issuer should talk to. The credentials for it are in the auth Secret from setup, which the tests never read.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `E2E_COMMAND_HOSTNAME` | yes | | Command instance hostname |
| `E2E_CERTIFICATE_TEMPLATE` | yes | | Certificate template short name |
| `E2E_CERTIFICATE_AUTHORITY_LOGICAL_NAME` | yes | | CA logical name in Command |
| `E2E_COMMAND_API_PATH` | no | `KeyfactorAPI` | API path |
| `E2E_CERTIFICATE_AUTHORITY_HOSTNAME` | no | | CA hostname |
| `E2E_ENROLLMENT_PATTERN_NAME` | no | | Enrollment pattern for the Issuer |
| `E2E_OWNER_ROLE_NAME` | no | | Owner role for the Issuer |
| `E2E_CERTIFICATE_COMMON_NAME` | no | `example.com` | Common name requested in the test Certificate |
| `E2E_KUBE_CONTEXT` | no | current context | kubeconfig context to test against |
| `E2E_KEEP_RESOURCES` | no | `false` | `true` leaves test namespaces in place for debugging |

### Preflight

Before any test runs, the suite checks that cert-manager and the Issuer CRDs are installed, that the issuer Deployment has an available replica, and that the auth Secret exists. If anything is missing it lists every problem and tells you to run `make e2e-setup`, rather than failing in the middle of a test. The CA trust Secret is optional; if setup created it, the test Issuer uses it.

### Tests

Each test creates its own `e2e-*` namespace and deletes it afterwards, so tests don't share state and a re-run starts clean.

| Test | What it verifies |
|------|------------------|
| `TestCertificateRequestIsIssued` | Creates an Issuer and waits for it to be Ready. Creates a Certificate, waits for cert-manager to create the CertificateRequest, and approves it. Waits for the request to be issued and the Certificate to be Ready. Then checks that the Secret holds a certificate matching its private key, with the requested common name and a currently valid lifetime. |

Approving a CertificateRequest needs permission to `approve` for the `issuers.command-issuer.keyfactor.com` signer, which cert-manager does not grant by default. A cluster-admin kubeconfig has it. If the approval is rejected, the failure message says so.

---

# Legacy Bash e2e suite (deprecated)

> **This suite is subject to deprecation** once the Go suite covers the same cases. It is kept working in the meantime. It is separate from the Go suite and shares no configuration with it: it uses `.env` and the variables below, not `e2e.env` and the `E2E_*` variables above.

This is a test suite intended to make it easy to run end-to-end tests on the command-cert-manager-issuer project. This suite can test the local changes of the Command issuer, and it is able to test existing Docker images.

The test suite does the following:
- Deploys command-cert-manager-issuer to a Kubernetes cluster with the desired version
- Creates an issuer (Issuer and ClusterIssuer)
- Creates a Certificate custom resource
- Waits for cert-manager to create a CertificateRequest, then signs the request
- Waits for the issuer to handle the CertificateRequest
- Verifies the CertificateRequest has been successfully processed and an issuer secret is created with the related certificate information.

This is currently configured as a Bash script, so it is necessary to run this on a UNIX-compatible machine.

## Requirements

**Local tools:**
- Docker (>= 28.2.2)
- kubectl (>= v1.32.2)
- helm (>= v3.17.1)
- cmctl (>= v2.1.1)
- Minikube (>= v1.35.0) - only required if using `USE_MINIKUBE=true`

**Kubernetes cluster:**
- By default, tests run against your current kubeconfig context
- Set `USE_MINIKUBE=true` to use minikube instead

**Command instance:**
- An available Command instance configured as described in the [root README](../README.md#configuring-command)
- OAuth credentials for API access
- An enrollment pattern (default: "Default Pattern") with CSR Enrollment enabled
- A security role (default: "InstanceOwner") with Enrollment permissions

On the Command side:
- An enrollment pattern is created called "Test Enrollment Pattern" that is has CSR Enrollment, CSR Generation, and PFX Enrollment enabled
- A security role by the name of "InstanceOwner" exists and has the ability to perform Enrollment

## Configuring the environment variables

command-cert-manager-issuer interacts with an external Command instance. An environment variable file `.env` can be used to store the environment variables to be used to talk to the Command instance.

A `.env.example` file is available as a template for your environment variables.

```bash
# copy .env.example to .env
cp .env.example .env
```

### Required variables

| Variable | Description |
|----------|-------------|
| `HOSTNAME` | Command instance hostname |
| `API_PATH` | API path (default: `KeyfactorAPI`) |
| `OAUTH_TOKEN_URL` | OAuth token endpoint URL |
| `OAUTH_CLIENT_ID` | OAuth client ID |
| `OAUTH_CLIENT_SECRET` | OAuth client secret |
| `CERTIFICATE_TEMPLATE` | Certificate template short name |
| `CERTIFICATE_AUTHORITY_LOGICAL_NAME` | CA logical name in Command |

### Optional variables

| Variable | Description | Default |
|----------|-------------|---------|
| `IMAGE_TAG` | Docker image version to test | `2.5.0` |
| `HELM_CHART_VERSION` | Helm chart version | `2.5.0` |
| `E2E_ENROLLMENT_PATTERN_NAME` | Enrollment pattern name | `Default Pattern` |
| `E2E_OWNER_ROLE_NAME` | Owner role name | `InstanceOwner` |
| `DISABLE_CA_CHECK` | Skip TLS CA verification | `false` |
| `USE_MINIKUBE` | Use minikube instead of current kubeconfig | `false` |
| `IMAGE_REGISTRY` | Registry to push local builds (when `IMAGE_TAG=local`) | - |

## Configuring the trusted certificate store

The issuer created in the end-to-end tests can leverage the `caSecretName` specification to determine a collection of CAs to trust in order to establish a trusted connection with the remote Keyfactor Command instance. The certificates defined in this secret will be pulled from the `certs` folder in this directory.

Place the CA certificates for the Keyfactor Command instance you'd like to connect to (the intermediate and/or root CAs) under `certs` directory.

> NOTE: This check can be disabled by setting the env variable `DISABLE_CA_CHECK=true`.

## Running the tests

### Using current kubeconfig context (default)

```bash
# Configure your .env file first
source .env

# Run the tests
./run_tests.sh
```

Or from the project root:
```bash
make test-e2e
```

### Using minikube

```bash
export USE_MINIKUBE=true
source .env
./run_tests.sh
```

### Testing a specific version

```bash
export IMAGE_TAG="2.4.0"
export HELM_CHART_VERSION="2.4.0"
source .env
./run_tests.sh
```

### Testing local changes

```bash
# With minikube (image built directly into minikube's docker)
export IMAGE_TAG="local"
export HELM_CHART_VERSION="local"
export USE_MINIKUBE=true
source .env
./run_tests.sh

# With a remote cluster (requires pushing to a registry)
export IMAGE_TAG="local"
export HELM_CHART_VERSION="local"
export IMAGE_REGISTRY="your-registry.com/your-repo"
source .env
./run_tests.sh
```
