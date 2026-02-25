# End-to-End Test Suite

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
