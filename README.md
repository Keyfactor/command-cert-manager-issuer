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

## Quick Start

The quick start guide will walk you through the process of installing the cert-manager external issuer for Keyfactor Command.
The controller image is pulled from [Docker Hub](https://hub.docker.com/r/m8rmclarenkf/command-cert-manager-external-issuer-controller).

###### To build  the container from sources, refer to the [Building Container Image from Source](#building-container-image-from-source) section.

### Requirements
* [Git](https://git-scm.com/)
* [Make](https://www.gnu.org/software/make/)
* [Docker](https://docs.docker.com/engine/install/) >= v20.10.0
* [Kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/) >= v1.11.3
* Kubernetes >= v1.19
	* [Kubernetes](https://kubernetes.io/docs/tasks/tools/), [Minikube](https://minikube.sigs.k8s.io/docs/start/), or [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/)
* [Keyfactor Command](https://www.keyfactor.com/products/command/) >= v10.1.0
* [cert-manager](https://cert-manager.io/docs/installation/) >= v1.11.0
* [cmctl](https://cert-manager.io/docs/reference/cmctl/)

Before starting, ensure that all of the above requirements are met, and that Keyfactor Command is properly configured. Refer 
to the [Keyfactor Configuration](#keyfactor-command-configuration) section for more information.
Additionally, verify that at least one Kubernetes node is running by running the following command:
```shell
kubectl get nodes
```

### Installation from Manifests

Once Kubernetes is running, a static installation of cert-manager can be installed with the following command:
```shell
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
```

###### :pushpin: Running the static cert-manager configuration is not recommended for production use. For more information, see [Installing cert-manager](https://cert-manager.io/docs/installation/).

Then, install the custom resource definitions (CRDs) for the cert-manager external issuer for Keyfactor Command:
```shell
make install
```

Finally, deploy the controller to the cluster:
```shell
make deploy
```

### Installation from Helm Chart

The cert-manager external issuer for Keyfactor Command can also be installed using a Helm chart. The chart is available in the [Command cert-manager Helm repository](https://keyfactor.github.io/command-cert-manager-issuer/).

First, add the Helm repository:
```bash
helm repo add command-issuer https://keyfactor.github.io/command-cert-manager-issuer
helm repo update
```

Then, install the chart:
```bash
helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer
```

Modifications can be made by overriding the default values in the `values.yaml` file with the `--set` flag. For example, to override the `replicaCount` value, run the following command:
```bash
helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer --set replicaCount=2
```

## Usage
The cert-manager external issuer for Keyfactor Command can be used to issue certificates from Keyfactor Command using cert-manager.

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
* `hostname` - The hostname of the Keyfactor Command server
* `commandSecretName` - The name of the Kubernetes `kubernetes.io/basic-auth` secret containing credentials to the Keyfactor instance
* `certificateTemplate` - The short name corresponding to a template in Command that will be used to issue certificates.
* `certificateAuthorityLogicalName` - The logical name of the CA to use to sign the certificate request
* `certificateAuthorityHostname` - The CAs hostname to use to sign the certificate request
* `caBundleSecretName` - The name of the Kubernetes secret containing the CA certificate. This field is optional and only required if the Command server is configured to use a self-signed certificate or with a certificate signed by an untrusted root.

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
  caBundleSecretName: ""
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
  caBundleSecretName: ""
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

## Annotation Overrides for Issuer and ClusterIssuer Resources
The Keyfactor Command external issuer for cert-manager allows you to override default settings in the Issuer and ClusterIssuer resources through the use of annotations. This gives you more granular control on a per-Certificate/CertificateRequest basis.

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

### How to Apply Annotations

To apply these annotations, include them in the metadata section of your CertificateRequest resource:

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  annotations:
    command-issuer.keyfactor.com/certificateTemplate: "Ephemeral2day"
    command-issuer.keyfactor.com/certificateAuthorityLogicalName: "InternalIssuingCA1"
    # ... other annotations
spec:
# ... rest of the spec
```

### Demo ClusterIssuer Usage with K8s Ingress
This demo will show how to use a ClusterIssuer to issue a certificate for an Ingress resource. The demo uses the Kubernetes 
`ingress-nginx` Ingress controller. If Minikube is being used, run the following command to enable the controller.
```shell
minikube addons enable ingress
kubectl get pods -n ingress-nginx
```

To manually deploy `ingress-nginx`, run the following command:
```shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.7.0/deploy/static/provider/cloud/deploy.yaml
```

Create a namespace for the demo:
```shell
kubectl create ns command-clusterissuer-demo
```

Deploy two Pods running the `hashicorp/http-echo` image:
```shell
cat <<EOF | kubectl -n command-clusterissuer-demo apply -f -
kind: Pod
apiVersion: v1
metadata:
  name: apple-app
  labels:
    app: apple
spec:
  containers:
    - name: apple-app
      image: hashicorp/http-echo
      args:
        - "-text=apple"
---
kind: Service
apiVersion: v1
metadata:
  name: apple-service
spec:
  selector:
    app: apple
  ports:
    - port: 5678 # Default port for image
---
kind: Pod
apiVersion: v1
metadata:
  name: banana-app
  labels:
    app: banana
spec:
  containers:
    - name: banana-app
      image: hashicorp/http-echo
      args:
        - "-text=banana"
---
kind: Service
apiVersion: v1
metadata:
  name: banana-service
spec:
  selector:
    app: banana
  ports:
    - port: 5678 # Default port for image
EOF
```

###### :pushpin: The above command creates two Pods and two Services. The Pods are running the `hashicorp/http-echo` image, which returns the text specified in the `-text` argument when the Pod is queried. The Services are used to expose the Pods to the cluster.

Create an Ingress resource to route traffic to the Pods:
```shell
cat <<EOF | kubectl -n command-clusterissuer-demo apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: command-ingress-demo
  annotations:
    ingress.kubernetes.io/rewrite-target: /
    cert-manager.io/issuer: clusterissuer-sample
    cert-manager.io/issuer-kind: ClusterIssuer
    cert-manager.io/issuer-group: command-issuer.keyfactor.com
    cert-manager.io/common-name: command-issuer-demo
spec:
  ingressClassName: nginx
  rules:
  - host: localhost
    http:
      paths:
        - path: /apple
          pathType: Prefix
          backend:
            service: 
              name: apple-service
              port: 
                number: 5678
        - path: /banana
          pathType: Prefix
          backend:
            service: 
              name: banana-service
              port: 
                number: 5678
  tls: # < placing a host in the TLS config will determine what ends up in the cert's subjectAltNames
  - hosts:
    - localhost
    secretName: command-ingress-cert # < cert-manager will store the created certificate in this secret.
EOF
```

Retrieve the name of the CertificateRequest resource created by cert-manager:
```shell
kubectl -n command-clusterissuer-demo get certificaterequest
```

Approve the CertificateRequest resource:
```shell
cmctl -n command-clusterissuer-demo approve <name>
```

Validate that the certificate was created:
```shell
kubectl -n command-clusterissuer-demo describe ingress command-ingress-demo
```

Test it out
```shell
curl -k https://localhost/apple
curl -k https://localhost/banana
```

Clean up
```shell
kubectl -n command-clusterissuer-demo delete ingress command-ingress-demo
kubectl -n command-clusterissuer-demo delete service apple-service banana-service
kubectl -n command-clusterissuer-demo delete pod apple-app banana-app
kubectl delete ns command-clusterissuer-demo
kubectl delete -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.7.0/deploy/static/provider/cloud/deploy.yaml
```

## Cleanup
To list the certificates and certificate requests created, run the following commands:
```shell
kubectl get certificates -n command-issuer-system
kubectl get certificaterequests -n command-issuer-system
```

To remove the certificate and certificate request resources, run the following commands:
```shell
kubectl delete certificate command-certificate -n command-issuer-system
kubectl delete certificaterequest command-certificate -n command-issuer-system
```

To list the issuer and cluster issuer resources created, run the following commands:
```shell
kubectl -n command-issuer-system get issuers.command-issuer.keyfactor.com
kubectl -n command-issuer-system get clusterissuers.command-issuer.keyfactor.com
```

To remove the issuer and cluster issuer resources, run the following commands:
```shell
kubectl -n command-issuer-system delete issuers.command-issuer.keyfactor.com <issuer-name>
kubectl -n command-issuer-system delete clusterissuers.command-issuer.keyfactor.com <issuer-name>
```

To remove the controller from the cluster, run:
```shell
make undeploy
```

To remove the custom resource definitions (CRDs) for the cert-manager external issuer for Keyfactor Command, run:
```shell
make uninstall
```

## Keyfactor Command Configuration
The Command Issuer for cert-manager populates metadata fields in Command pertaining to the K8s cluster and cert-manager Issuer/ClusterIssuer.
Before configuring the issuer, create these metadata fields. These fields will be populated using the `kfutil` Keyfactor command line tool that offers convenient and powerful
command line access to the Keyfactor platform. Before proceeding, ensure that `kfutil` is installed and configured
by following the instructions here: [https://github.com/Keyfactor/kfutil](https://github.com/Keyfactor/kfutil)

Use the `import` command to import the metadata fields into Command:
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
kfutil import --metadata --file metadata.json
```

## Building Container Image from Source

### Requirements
* [Golang](https://golang.org/) >= v1.19

Building the container from source first runs appropriate test cases, which requires all requirements also listed in the
Quick Start section. As part of this testing is an enrollment of a certificate with Command, so a running instance of Command
is also required.

The following environment variables must be exported before building the container image:
* `COMMAND_HOSTNAME` - The hostname of the Command server to use for testing.
* `COMMAND_USERNAME` - The username of an authorized Command user to use for testing.
* `COMMAND_PASSWORD` - The password of the authorized Command user to use for testing.
* `COMMAND_CERTIFICATE_TEMPLATE` - The name of the certificate template to use for testing.
* `COMMAND_CERTIFICATE_AUTHORITY_LOGICAL_NAME` - The logical name of the certificate authority to use for testing.
* `COMMAND_CERTIFICATE_AUTHORITY_HOSTNAME` - The hostname of the certificate authority to use for testing.
* `COMMAND_CA_CERT_PATH` - A relative or absolute path to the CA certificate that the Command server uses for TLS. The file must include the certificate in PEM format.

To build the cert-manager external issuer for Keyfactor Command, run:
```shell
make docker-build
```
