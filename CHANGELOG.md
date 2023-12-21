# v1.0.6

## Features
* feat(helm): Rename `secureMetrics` to `metrics` and add `metrics.secure` and `metrics.metricsAddress` as configuration values. This way, Prometheus can scrape the controller manager metrics without the secure metrics proxy.
* feat(helm): Add configuration element in Helm chart default values file to configure container ports on the controller manager container.

## Fixes
* fix(deps): Update golang.org/x/net to v0.19.0
* fix(dockerfile): Upgrade builder image to golang:1.20 to address [CVE-2023-38408](https://scout.docker.com/vulnerabilities/id/CVE-2023-38408?utm_source=hub&utm_medium=ExternalLink&_gl=1*hbs4zp*_ga*MTU5MTQ4Mzk3MC4xNjkxNDI2NjAy*_ga_XJWPQMJYHQ*MTcwMzE4NzcyNC4xMDEuMS4xNzAzMTg4OTUxLjM3LjAuMA..)

# v1.0.5

## Features
* feat(controller): Implement Kubernetes `client-go` REST client for Secret/ConfigMap retrieval to bypass `controller-runtime` caching system. This enables the reconciler to retrieve Secret and ConfigMap resources at the namespace scope with only namespace-level permissions.

## Fixes
* fix(helm): Add configuration flag to configure chart to either grant cluster-scoped or namespace-scoped access to Secret and ConfigMap API
* fix(controller): Add logic to read secret from reconciler namespace or Issuer namespace depending on Helm configuration.

# v1.0.4

## Features
* feat(signer): Signer recognizes `metadata.command-issuer.keyfactor.com/<metadata-field-name>: <metadata-value>` annotations on the CertificateRequest resource and uses them to populate certificate metadata in Command.
* feat(release): Container build and release now uses GitHub Actions.

## Fixes
* fix(helm): CRDs now correspond to correct values for the `command-issuer`.
* fix(helm): Signer Helm Chart now includes a `secureMetrics` value to enable/disable sidecar RBAC container for further protection of the `/metrics` endpoint.
* fix(signer): Signer now returns CA chain bytes instead of appending to the leaf certificate.
* fix(role): Removed permissions for `configmaps` resource types for the `leader-election-role` role.
