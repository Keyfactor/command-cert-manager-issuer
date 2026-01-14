<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Keyfactor Command Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/command-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/command-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)
![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square)

A Helm chart for the Keyfactor Command External Issuer for cert-manager.

The Command external issuer for cert-manager allows users to enroll certificates from Keyfactor Command using cert-manager.

## Installation

### Add Helm Repository

```shell
helm repo add command-issuer https://keyfactor.github.io/command-cert-manager-issuer
helm repo update
```

### Install Chart

```shell
helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer \
    --namespace command-issuer-system \
    --create-namespace \
    --set image.repository=<your container registry>/keyfactor/command-cert-manager-issuer \
    --set image.tag=<tag> \
    --set crd.create=true \
    # --set image.pullPolicy=Never # Only required if using a local image
```

Modifications can be made by overriding the default values in the `values.yaml` file with the `--set` flag. For example, to override the `secretConfig.useClusterRoleForSecretAccess` to configure the chart to use a cluster role for secret access, run the following command:

```shell
helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer \
    --namespace command-issuer-system \
    --create-namespace \
    --set image.repository=<your container registry>/keyfactor/command-cert-manager-issuer \
    --set image.tag=<tag> \
    --set crd.create=true \
    --set secretConfig.useClusterRoleForSecretAccess=true
```

Modifications can also be made by modifying the `values.yaml` file directly. For example, to override the `secretConfig.useClusterRoleForSecretAccess` value to configure the chart to use a cluster role for secret access, modify the `secretConfig.useClusterRoleForSecretAccess` value in the `values.yaml` file by creating an override file:
```yaml
cat <<EOF > override.yaml
secretConfig:
    useClusterRoleForSecretAccess: true
EOF
```
Then, use the `-f` flag to specify the `values.yaml` file:
```shell
helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer \
    --namespace command-issuer-system \
    -f override.yaml
```

## Configuration

The following table lists the configurable parameters of the `command-cert-manager-issuer` chart and their default values.

| Parameter                                    | Description                                                                                                                              | Default                                               |
|----------------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------|
| `replicaCount`                               | Number of replica command-cert-manager-issuers to run                                                                                    | `1`                                                   |
| `image.repository`                           | Image repository                                                                                                                         | `ghcr.io/keyfactor/command-cert-manager-issuer`       |
| `image.pullPolicy`                           | Image pull policy                                                                                                                        | `IfNotPresent`                                        |
| `image.tag`                                  | Image tag                                                                                                                                | `""`                                                  |
| `imagePullSecrets`                           | Image pull secrets                                                                                                                       | `[]`                                                  |
| `nameOverride`                               | Name override                                                                                                                            | `""`                                                  |
| `fullnameOverride`                           | Full name override                                                                                                                       | `""`                                                  |
| `crd.create`                                 | Specifies if CRDs will be created                                                                                                        | `true`                                                |
| `crd.annotations`                            | Annotations to add to the CRD                                                                                                            | `{}`                                                  |
| `serviceAccount.create`                      | Specifies if a service account should be created                                                                                         | `true`                                                |
| `serviceAccount.annotations`                 | Annotations to add to the service account                                                                                                | `{}`                                                  |
| `serviceAccount.name`                        | Name of the service account to use                                                                                                       | `""` (uses the fullname template if `create` is true) |
| `podAnnotations`                             | Annotations for the pod                                                                                                                  | `{}`                                                  |
| `podSecurityContext.runAsNonRoot`            | Run pod as non-root                                                                                                                      | `true`                                                |
| `securityContext`                            | Security context for the pod                                                                                                             | `{}` (with commented out options)                     |
| `resources`                                  | CPU/Memory resource requests/limits                                                                                                      | `{}` (with commented out options)                     |
| `nodeSelector`                               | Node labels for pod assignment                                                                                                           | `{}`                                                  |
| `tolerations`                                | Tolerations for pod assignment                                                                                                           | `[]`                                                  |
| `secretConfig.useClusterRoleForSecretAccess` | Specifies if the ServiceAccount should be granted access to the Secret resource using a ClusterRole                                      | `false`                                               |
| `defaultHealthCheckInterval`                 | Specifies the default health check interval for issuers                                                        | `""` (uses the default in the code which is 60s)                                 |
