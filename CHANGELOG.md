# v1.0.4

## Features
* feat(signer): Signer recognizes `metadata.command-issuer.keyfactor.com/<metadata-field-name>: <metadata-value>` annotations on the CertificateRequest resource and uses them to populate certificate metadata in Command.
* feat(release): Container build and release now uses GitHub Actions.

## Fixes
* fix(helm): CRDs now correspond to correct values for the `command-issuer`.
* fix(helm): Signer Helm Chart now includes a `secureMetrics` value to enable/disable sidecar RBAC container for further protection of the `/metrics` endpoint.
* fix(signer): Signer now returns CA chain bytes instead of appending to the leaf certificate.
* fix(role): Removed permissions for `configmaps` resource types for the `leader-election-role` role.

# v1.0.5

## Features
* feat(controller): Implement Kubernetes `client-go` REST client for Secret/ConfigMap retrieval to bypass `controller-runtime` caching system. This enables the reconciler to retrieve Secret and ConfigMap resources at the namespace scope with only namespace-level permissions.

## Fixes
* fix(helm): Add configuration flag to configure chart to either grant cluster-scoped or namespace-scoped access to Secret and ConfigMap API
* fix(controller): Add logic to read secret from reconciler namespace or Issuer namespace depending on Helm configuration.

# v2.0.0

## Features
- Implement OAuth 2.0 Client Credentials grant as an authentication mechanism.
- Implement Azure Workload Identity as an authentication mechanism.

## Chores
- Refactor Command signer module to remove tight dependency on Issuer/ClusterIssuer types.
- Migrate Kubebuilder from go/v3 to go/v4:
    - Upgrade kustomize version to v5.3.0.
    - Upgrade controller-gen to v0.14.0.
- Refactor unit tests to use fake Command API instead of requiring live Command server.
- Write e2e integration test.

# v2.0.1

## Fixes
- Change Helm release trigger from `v*` to `release-*` to support Keyfactor Bootstrap Workflow

# v2.0.2

## Fixes
- Bug fix in Helm chart release action

# v2.1.0

## Fixes
- Updated library golang.org/x/crypto to version v0.33.0 to address authorization bypass vulnerability (https://github.com/advisories/GHSA-v778-237x-gjrc)
- Bug fix for Google ambient credentials

# v2.1.1

## Fixes
- Update Helm chart deployment template to resolve Docker image metadata issue.

## Chores
- Update documentation for more clear instructions on deploying workloads to Azure Kubernetes Service and Google Kubernetes Engine, as well as permissions needed on Command Security Roles.
