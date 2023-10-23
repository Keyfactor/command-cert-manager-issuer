<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Keyfactor Command Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/command-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/command-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The Command external issuer for cert-manager allows users to enroll certificates with a CA managed by Keyfactor Command using cert-manager. This allows security administrators to manage the lifecycle of certificates for Kubernetes applications.

Cert-manager is a native Kubernetes certificate management controller which allows applications to get their certificates from a variety of CAs (Certification Authorities). It ensures certificates are valid and up to date, it also attempts to renew certificates at a configured time before expiration.

## Community supported
We welcome contributions.

The cert-manager external issuer for Keyfactor command is open source and community supported, meaning that there is **no SLA** applicable for these tools.

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, see the [contribution guidelines](https://github.com/Keyfactor/command-k8s-csr-signer/blob/main/CONTRIBUTING.md) and use the **[Pull requests](../../pulls)** tab.

* [Installation](docs/install.markdown)
* [Usage](docs/config_usage.markdown)
* [Example Usage](docs/example.markdown)
* [Customization](docs/annotations.markdown)
* [Testing the Source](docs/testing.markdown)
