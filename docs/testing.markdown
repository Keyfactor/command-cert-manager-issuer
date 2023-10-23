<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Testing the Controller Source Code

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/command-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/command-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)


### Documentation Tree
* [Installation](install.markdown)
* [Usage](config_usage.markdown)
* [Example Usage](example.markdown)
* [Customization](annotations.markdown)

The test cases for the controller require a set of environment variables to be set. These variables are used to
authenticate to the Command server and to enroll a certificate. The test cases are run using the `make test` command.

The following environment variables must be exported before testing the controller:
* `COMMAND_HOSTNAME` - The hostname of the Command server to use for testing.
* `COMMAND_USERNAME` - The username of an authorized Command user to use for testing.
* `COMMAND_PASSWORD` - The password of the authorized Command user to use for testing.
* `COMMAND_CERTIFICATE_TEMPLATE` - The name of the certificate template to use for testing.
* `COMMAND_CERTIFICATE_AUTHORITY_LOGICAL_NAME` - The logical name of the certificate authority to use for testing.
* `COMMAND_CERTIFICATE_AUTHORITY_HOSTNAME` - The hostname of the certificate authority to use for testing.
* `COMMAND_CA_CERT_PATH` - A relative or absolute path to the CA certificate that the Command server uses for TLS. The file must include the certificate in PEM format.

To build the cert-manager external issuer for Keyfactor Command, run:
```shell
make test
```