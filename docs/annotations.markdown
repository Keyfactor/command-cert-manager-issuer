<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Annotation Overrides for Issuer and ClusterIssuer Resources

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/command-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/command-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The Keyfactor Command external issuer for cert-manager allows you to override default settings in the Issuer and ClusterIssuer resources through the use of annotations. This gives you more granular control on a per-Certificate/CertificateRequest basis.

### Documentation Tree
* [Installation](install.markdown)
* [Usage](config_usage.markdown)
* [Example Usage](example.markdown)
* [Testing the Source](testing.markdown)

### Supported Annotations
Here are the supported annotations that can override the default values:

- **`command-issuer.keyfactor.com/certificateTemplate`**: Overrides the `certificateTemplate` field from the resource spec.

    ```yaml
    command-issuer.keyfactor.com/certificateTemplate: "Ephemeral2day"
    ```

- **`command-issuer.keyfactor.com/certificateAuthorityLogicalName`**: Specifies the Certificate Authority (CA) logical name to use, overriding the default CA specified in the resource spec.

    ```yaml
    command-issuer.keyfactor.com/certificateAuthorityLogicalName: "InternalIssuingCA1"
    ```

- **`command-issuer.keyfactor.com/certificateAuthorityHostname`**: Specifies the Certificate Authority (CA) hostname to use, overriding the default CA specified in the resource spec.

    ```yaml
    command-issuer.keyfactor.com/certificateAuthorityHostname: "example.com"
    ```

### Metadata Annotations

The Keyfactor Command external issuer for cert-manager also allows you to specify Command Metadata through the use of annotations. Metadata attached to a certificate request will be stored in Command and can be used for reporting and auditing purposes. The syntax for specifying metadata is as follows:
```yaml
metadata.command-issuer.keyfactor.com/<metadata-field-name>: <metadata-value>
```

###### :pushpin: The metadata field name must match a name of a metadata field in Command exactly. If the metadata field name does not match, the CSR enrollment will fail.

### How to Apply Annotations

To apply these annotations, include them in the metadata section of your CertificateRequest resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  annotations:
    command-issuer.keyfactor.com/certificateTemplate: "Ephemeral2day"
    command-issuer.keyfactor.com/certificateAuthorityLogicalName: "InternalIssuingCA1"
    metadata.command-issuer.keyfactor.com/ResponsibleTeam: "theResponsibleTeam@example.com"
    # ... other annotations
spec:
# ... the rest of the spec
```