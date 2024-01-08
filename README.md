# command-cert-manager-issuer

The Command external issuer for cert-manager allows users to enroll certificates with a CA managed by Keyfactor Command using cert-manager, allowing security administrators to manage the lifecycle of certificates for Kubernetes applications.

#### Integration status: Pilot - Ready for use in test environments. Not for use in production.



## Support for command-cert-manager-issuer

command-cert-manager-issuer is open source and supported on best effort level for this tool/library/client.  This means customers can report Bugs, Feature Requests, Documentation amendment or questions as well as requests for customer information required for setup that needs Keyfactor access to obtain. Such requests do not follow normal SLA commitments for response or resolution. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com/

###### To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.



<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/command-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/command-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The Command external issuer for cert-manager allows users to enroll certificates with a CA managed by Keyfactor Command using cert-manager. This allows security administrators to manage the lifecycle of certificates for Kubernetes applications.

Cert-manager is a native Kubernetes certificate management controller which allows applications to get their certificates from a variety of CAs (Certification Authorities). It ensures certificates are valid and up to date, it also attempts to renew certificates at a configured time before expiration.


* [Installation](docs/install.markdown)
* [Usage](docs/config_usage.markdown)
* [Example Usage](docs/example.markdown)
* [Customization](docs/annotations.markdown)
* [Testing the Source](docs/testing.markdown)

