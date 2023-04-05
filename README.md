<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Keyfactor Command Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/command-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/command-k8s-csr-signer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The Command external issuer for cert-manager allows users to enroll certificates with a CA managed by Keyfactor Command using cert-manager. This allows security administrators to manage the lifecycle of certificates for Kubernetes applications.

Cert-manager is a native Kubernetes certificate management controller which allows applications to get their certificates from a variety of CAs (Certification Authorities). It ensures certificates are valid and up to date, it also attempts to renew certificates at a configured time before expiration.

## Community supported
We welcome contributions.

The cert-manager external issuer for Keyfactor command is open source and community supported, meaning that there is **no SLA** applicable for these tools.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, see the [contribution guidelines](https://github.com/Keyfactor/command-k8s-csr-signer/blob/main/CONTRIBUTING.md) and use the **[Pull requests](../../pulls)** tab.

## Requirements
### To build
* [Git](https://git-scm.com/)
* [Golang](https://golang.org/) >= v1.19
* [Kubebuilder](https://book.kubebuilder.io/quick-start.html#installation) >= v2.3.1
* [Kustomize](https://kustomize.io/) >= v3.8.1

### To use
* [Keyfactor Command](https://www.keyfactor.com/products/command/) >= v10.1.0
* [Make](https://www.gnu.org/software/make/)
* [Docker](https://docs.docker.com/engine/install/) >= v20.10.0
* [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) >= v1.11.3
* Kubernetes >= v1.19
	* [Kubernetes](https://kubernetes.io/docs/tasks/tools/), [Minikube](https://minikube.sigs.k8s.io/docs/start/), or [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
* [cert-manager](https://cert-manager.io/docs/installation/) >= v1.11.0

To quickly create a Kubernetes cluster for testing purposes, you can use [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/).
```shell
kind create cluster
```
To see the single node for the cluster, run:
```shell
kubectl get nodes
```

## Building Container Image from Source
To build the cert-manager external issuer for Keyfactor Command, run:
```shell
make docker-build
```

## Installation
Install the static cert-manager configuration:
```shell
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
```

To install the custom resource definitions (CRDs) for the cert-manager external issuer for Keyfactor Command, run:
```shell
make install
```

To deploy the controller to the cluster, run:
```shell
make deploy
```

## Usage
Create a `kubernetes.io/basic-auth` secret with the Keyfactor Command username and password:
```shell
kubectl -n command-issuer-system create secret tls command-secret --username=USERNAME --password=PASSWORD
```

Create a Command Issuer and ClusterIssuer:
```shell
cat <<EOF >> command-issuer.yaml
apiVersion: command-issuer.keyfactor.io/v1alpha1
kind: Issuer
metadata:
  labels:
    app.kubernetes.io/name: issuer
    app.kubernetes.io/instance: issuer-sample
    app.kubernetes.io/part-of: command-issuer
    app.kubernetes.io/created-by: command-issuer
name: issuer-sample
spec:
  # Hostname is the hostname of the Keyfactor server
  hostname: ""
  commandSecretName: ""
  # The Command template to use for the certificate request
  certificateTemplate: ""
  # The logical name of the CA to use to sign the certificate request
  certificateAuthorityLogicalName: ""
  # The CAs hostname to use to sign the certificate request
  certificateAuthorityHostname: ""
kubectl -n command-issuer-system apply -f issuer.yaml
cat <<EOF >> clusterissuer.yaml
apiVersion: command-issuer.keyfactor.com/v1alpha1
kind: ClusterIssuer
metadata:
  labels:
    app.kubernetes.io/name: clusterissuer
    app.kubernetes.io/instance: clusterissuer-sample
    app.kubernetes.io/part-of: command-issuer
    app.kubernetes.io/created-by: command-issuer
  name: clusterissuer-sample
spec:
  # Hostname is the hostname of the Keyfactor server
  hostname: ""
  commandSecretName: ""
  # The Command template to use for the certificate request
  certificateTemplate: ""
  # The logical name of the CA to use to sign the certificate request
  certificateAuthorityLogicalName: ""
  # The CAs hostname to use to sign the certificate request
  certificateAuthorityHostname: ""
EOF
kubectl -n command-issuer-system apply -f clusterissuer.yaml
```

To create a certificate, create a CertificateRequest resource:
```shell
cat <<EOF >> certificate.yaml
apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata:
  name: command-certificate
spec:
  request: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURSBSRVFVRVNULS0tLS0KTUlJQ2REQ0NBVndDQVFBd0x6RUxNQWtHQTFVRUN4TUNTVlF4SURBZUJnTlZCQU1NRjJWcVltTmhYM1JsY25KaApabTl5YlY5MFpYTjBZV05qTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF4blNSCklqZDZSN2NYdUNWRHZscXlFcUhKalhIazljN21pNTdFY3A1RXVnblBXa0YwTHBVc25PMld6WTE1bjV2MHBTdXMKMnpYSURhS3NtZU9ZQzlNOWtyRjFvOGZBelEreHJJWk5SWmg0cUZXRmpyNFV3a0EySTdUb05veitET2lWZzJkUgo1cnNmaFdHMmwrOVNPT3VscUJFcWVEcVROaWxyNS85OVpaemlBTnlnL2RiQXJibWRQQ1o5OGhQLzU0NDZhci9NCjdSd2ludjVCMnNRcWM0VFZwTTh3Nm5uUHJaQXA3RG16SktZbzVOQ3JyTmw4elhIRGEzc3hIQncrTU9DQUw0T00KTkJuZHpHSm5KenVyS0c3RU5UT3FjRlZ6Z3liamZLMktyMXRLS3pyVW5keTF1bTlmTWtWMEZCQnZ0SGt1ZG0xdwpMUzRleW1CemVtakZXQi9yRVFJREFRQUJvQUF3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUJhdFpIVTdOczg2Cmgxc1h0d0tsSi95MG1peG1vRWJhUTNRYXAzQXVFQ2x1U09mdjFDZXBQZjF1N2dydEp5ZGRha1NLeUlNMVNzazAKcWNER2NncUsxVVZDR21vRkp2REZEaEUxMkVnM0ZBQ056UytFNFBoSko1N0JBSkxWNGZaeEpZQ3JyRDUxWnk3NgpPd01ORGRYTEVib0w0T3oxV3k5ZHQ3bngyd3IwWTNZVjAyL2c0dlBwaDVzTHl0NVZOWVd6eXJTMzJYckJwUWhPCnhGMmNNUkVEMUlaRHhuMjR2ZEtINjMzSFo1QXd0YzRYamdYQ3N5VW5mVUE0ZjR1cHBEZWJWYmxlRFlyTW1iUlcKWW1NTzdLTjlPb0MyZ1lVVVpZUVltdHlKZTJkYXlZSHVyUUlpK0ZsUU5zZjhna1hYeG45V2drTnV4ZTY3U0x5dApVNHF4amE4OCs1ST0KLS0tLS1FTkQgQ0VSVElGSUNBVEUgUkVRVUVTVC0tLS0t
  issuerRef:
    name: issuer-sample
    group: command-issuer.keyfactor.com
    kind: Issuer
EOF
kubectl -n command-issuer-system apply -f certificate.yaml
```

The certificate must then be approved by an authorized service account. This can be done manually by running the following command:
```shell
cmctl approve certificate command-certificate
```

## Cleanup
To remove the controller from the cluster, run:
```shell
make undeploy
```

To remove the custom resource definitions (CRDs) for the cert-manager external issuer for Keyfactor command, run:
```shell
make uninstall
```