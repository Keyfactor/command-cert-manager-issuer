<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Command Cert Manager Issuer Usage

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/command-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/command-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

The cert-manager external issuer for Keyfactor Command can be used to issue certificates from Keyfactor Command using cert-manager.

### Documentation Tree
* [Installation](install.markdown)
* [Example Usage](example.markdown)
* [Customization](annotations.markdown)
* [Testing the Source](testing.markdown)

### Keyfactor Command Configuration
The Command Issuer for cert-manager populates metadata fields on issued certificates in Command pertaining to the K8s cluster and cert-manager Issuer/ClusterIssuer. Before deploying Issuers/ClusterIssuers, these metadata fields must be created in Command. To easily create these metadata fields, use the `kfutil` Keyfactor command line tool that offers convenient and powerful command line access to the Keyfactor platform. Before proceeding, ensure that `kfutil` is installed and configured by following the instructions here: [https://github.com/Keyfactor/kfutil](https://github.com/Keyfactor/kfutil).

Then, use the `import` command to import the metadata fields into Command:
```shell
cat <<EOF >> metadata.json
{
    "Collections": [],
    "MetadataFields": [
        {
            "AllowAPI": true,
            "DataType": 1,
            "Description": "The namespace that the issuer resource was created in.",
            "Name": "Issuer-Namespace"
        },
        {
            "AllowAPI": true,
            "DataType": 1,
            "Description": "The certificate reconcile ID that the controller used to issue this certificate.",
            "Name": "Controller-Reconcile-Id"
        },
        {
            "AllowAPI": true,
            "DataType": 1,
            "Description": "The namespace that the CertificateSigningRequest resource was created in.",
            "Name": "Certificate-Signing-Request-Namespace"
        },
        {
            "AllowAPI": true,
            "DataType": 1,
            "Description": "The namespace that the controller container is running in.",
            "Name": "Controller-Namespace"
        },
        {
            "AllowAPI": true,
            "DataType": 1,
            "Description": "The type of issuer that the controller used to issue this certificate.",
            "Name": "Controller-Kind"
        },
        {
            "AllowAPI": true,
            "DataType": 1,
            "Description": "The group name of the resource that the Issuer or ClusterIssuer controller is managing.",
            "Name": "Controller-Resource-Group-Name"
        },
        {
            "AllowAPI": true,
            "DataType": 1,
            "Description": "The name of the K8s issuer resource",
            "Name": "Issuer-Name"
        }
    ],
    "ExpirationAlerts": [],
    "IssuedCertAlerts": [],
    "DeniedCertAlerts": [],
    "PendingCertAlerts": [],
    "Networks": [],
    "WorkflowDefinitions": [],
    "BuiltInReports": [],
    "CustomReports": [],
    "SecurityRoles": []
}
EOF
kfutil import --metadata --file metadata.json
```

### Authentication
Authentication to the Command platform is done using basic authentication. The credentials must be provided as a Kubernetes `kubernetes.io/basic-auth` secret. These credentials should be for a user with "Certificate Enrollment: Enroll CSR" and "API: Read" permissions in Command.

Create a `kubernetes.io/basic-auth` secret with the Keyfactor Command username and password:
```shell
cat <<EOF | kubectl -n command-issuer-system apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: command-secret
type: kubernetes.io/basic-auth
data:
  username: <base64 encoded (domain\\)username>
  password: <base64 encoded password>
EOF
```

If the Helm chart was deployed with the `--set "secretConfig.useClusterRoleForSecretAccess=true"` flag, the secret must be created in the same namespace as any Issuer resources deployed. Otherwise, the secret must be created in the same namespace as the controller.

If the Command server is configured to use a self-signed certificate or with a certificate signed by an untrusted root, the CA certificate must be provided as a Kubernetes secret.
```shell
kubectl -n command-issuer-system create secret generic command-ca-secret --from-file=ca.crt
```

### Creating Issuer and ClusterIssuer resources
The `command-issuer.keyfactor.com/v1alpha1` API version supports Issuer and ClusterIssuer resources.
The Command controller will automatically detect and process resources of both types.

The Issuer resource is namespaced, while the ClusterIssuer resource is cluster-scoped.
For example, ClusterIssuer resources can be used to issue certificates for resources in multiple namespaces, whereas Issuer resources can only be used to issue certificates for resources in the same namespace.

The `spec` field of both the Issuer and ClusterIssuer resources use the following fields:
* `hostname` - The hostname of the Keyfactor Command server - The signer sets the protocol to `https` and automatically trims the trailing path from this field, if it exists. Additionally, the base Command API path is automatically set to `/KeyfactorAPI` and cannot be changed.
* `commandSecretName` - The name of the Kubernetes `kubernetes.io/basic-auth` secret containing credentials to the Keyfactor instance
* `certificateTemplate` - The short name corresponding to a template in Command that will be used to issue certificates.
* `certificateAuthorityLogicalName` - The logical name of the CA to use to sign the certificate request
* `certificateAuthorityHostname` - The CAs hostname to use to sign the certificate request
* `caSecretName` - The name of the Kubernetes secret containing the CA certificate. This field is optional and only required if the Command server is configured to use a self-signed certificate or with a certificate signed by an untrusted root.

###### If a different combination of hostname/certificate authority/certificate profile/end entity profile is required, a new Issuer or ClusterIssuer resource must be created. Each resource instantiation represents a single configuration.

The following is an example of an Issuer resource:
```shell
cat <<EOF >> command-issuer.yaml
apiVersion: command-issuer.keyfactor.com/v1alpha1
kind: Issuer
metadata:
  labels:
    app.kubernetes.io/name: issuer
    app.kubernetes.io/instance: issuer-sample
    app.kubernetes.io/part-of: command-issuer
    app.kubernetes.io/created-by: command-issuer
name: issuer-sample
spec:
  hostname: ""
  commandSecretName: ""
  certificateTemplate: ""
  certificateAuthorityLogicalName: ""
  certificateAuthorityHostname: ""
  caSecretName: ""
EOF
kubectl -n command-issuer-system apply -f command-issuer.yaml
```

###### :pushpin: Issuers can only issue certificates in the same namespace as the issuer resource. To issue certificates in multiple namespaces, use a ClusterIssuer.

The following is an example of a ClusterIssuer resource:
```shell
cat <<EOF >> command-clusterissuer.yaml
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
  hostname: ""
  commandSecretName: ""
  certificateTemplate: ""
  certificateAuthorityLogicalName: ""
  certificateAuthorityHostname: ""
  caSecretName: ""
EOF
kubectl -n command-issuer-system apply -f command-clusterissuer.yaml
```

###### :pushpin: ClusterIssuers can issue certificates in any namespace. To issue certificates in a single namespace, use an Issuer.

To create new resources from the above examples, replace the empty strings with the appropriate values and apply the resources to the cluster:
```shell
kubectl -n command-issuer-system apply -f issuer.yaml
kubectl -n command-issuer-system apply -f clusterissuer.yaml
```

### Using Issuer and ClusterIssuer resources
Once the Issuer and ClusterIssuer resources are created, they can be used to issue certificates using cert-manager.
The two most important concepts are `Certificate` and `CertificateRequest` resources. `Certificate`
resources represent a single X.509 certificate and its associated attributes, and automatically renews the certificate
and keeps it up to date. When `Certificate` resources are created, they create `CertificateRequest` resources, which
use an Issuer or ClusterIssuer to actually issue the certificate.

###### To learn more about cert-manager, see the [cert-manager documentation](https://cert-manager.io/docs/).

The following is an example of a Certificate resource. This resource will create a corresponding CertificateRequest resource,
and will use the `issuer-sample` Issuer resource to issue the certificate. Once issued, the certificate will be stored in a
Kubernetes secret named `command-certificate`.
```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: command-certificate
spec:
  commonName: command-issuer-sample
  secretName: command-certificate
  issuerRef:
    name: issuer-sample
    group: command-issuer.keyfactor.com
    kind: Issuer
```

###### :pushpin: Certificate resources support many more fields than the above example. See the [Certificate resource documentation](https://cert-manager.io/docs/usage/certificate/) for more information.

###### :pushpin: Since this certificate request called `command-certificate` is configured to use `issuer-sample`, it must be deployed in the same namespace as `issuer-sample`.

Similarly, a CertificateRequest resource can be created directly. The following is an example of a CertificateRequest resource.
```yaml
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
```

### Approving Certificate Requests
Unless the cert-manager internal approver automatically approves the request, newly created CertificateRequest resources
will be in a `Pending` state until they are approved. CertificateRequest resources can be approved manually by using
[cmctl](https://cert-manager.io/docs/reference/cmctl/#approve-and-deny-certificaterequests). The following is an example
of approving a CertificateRequest resource named `command-certificate` in the `command-issuer-system` namespace.
```shell
cmctl -n command-issuer-system approve ejbca-certificate
```

Once a certificate request has been approved, the certificate will be issued and stored in the secret specified in the
CertificateRequest resource. The following is an example of retrieving the certificate from the secret.
```shell
kubectl get secret command-certificate -n command-issuer-system -o jsonpath='{.data.tls\.crt}' | base64 -d
```

###### To learn more about certificate approval and RBAC configuration, see the [cert-manager documentation](https://cert-manager.io/docs/concepts/certificaterequest/#approval).

###### :pushpin: If the certificate was issued successfully, the Approved and Ready field will both be set to `True`.

Next, see the [example usage](example.markdown) documentation for a complete example of using the Command Issuer for cert-manager.