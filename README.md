<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Keyfactor Command Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/ejbca-k8s-csr-signer)](https://goreportcard.com/report/github.com/Keyfactor/ejbca-k8s-csr-signer)
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

## Configure Keyfactor Command
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

## Installation
Install the static cert-manager configuration:
```shell
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
```

:pushpin: **Note:** Running the static cert-manager configuration is not reccomended for production use. For more information, see [Installing cert-manager](https://cert-manager.io/docs/installation/).

To install the custom resource definitions (CRDs) for the cert-manager external issuer for Keyfactor Command, run:
```shell
make install
```

To deploy the controller to the cluster, run:
```shell
make deploy
```

Ensure that the CRDs are installed:
```shell
kubectl api-resources -n command-issuer-system --api-group command-issuer.keyfactor.com
```

Verify that the controller is running:
```shell
kubectl get ns
kubectl get pods -n command-issuer-system
```

## Usage
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

Create a Command Issuer resource:
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
kubectl -n command-issuer-system apply -f command-issuer.yaml
```

:pushpin: **Note:** Issuers can only issue certificates in the same namespace as the issuer resource. To issue certificates in multiple namespaces, use a ClusterIssuer.

Create a Command ClusterIssuer resource:
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
kubectl -n command-issuer-system apply -f command-clusterissuer.yaml
```

:pushpin: **Note:** ClusterIssuers can issue certificates in any namespace. To issue certificates in a single namespace, use an Issuer.

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

:pushpin: **Note:** Since this certificate request called `command-certificate` is configured to use `issuer-sample`, it must be deployed in the same namespace as `issuer-sample`.

The certificate must then be approved by an authorized service account. This can be done manually by running the following command:
```shell
cmctl -n command-issuer-system approve command-certificate
```

Review the status of the certificate request:
```shell
kubectl -n command-issuer-system get certificaterequest
```

:pushpin: **Note:** If the certificate was issued successfully, the Approved and Ready field will both be set to `True`.

### Demo ClusterIssuer Usage with K8s Ingress
This demo will show how to use the ClusterIssuer to issue a certificate for an Ingress resource. The application deployed is incredibly simple, and is only meant to demonstrate the use of the ClusterIssuer.

Apply the `ingress-nginx` Ingress Controller:
```shell
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/controller-v1.7.0/deploy/static/provider/cloud/deploy.yaml
```

Create a namespace for the demo:
```shell
kubectl create ns command-clusterissuer-demo
```

Create two K8s Pods running the `hashicorp/http-echo` image:
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

:pushpin: **Note:** The above command creates two Pods and two Services. The Pods are running the `hashicorp/http-echo` image, which simply returns the text specified in the `-text` argument when the Pod is queried. The Services are used to expose the Pods to the cluster.

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
To remove the issuers from the cluster, run:
```shell
kubectl delete -f command-clusterissuer.yaml
kubectl delete -f command-issuer.yaml
```

To remove the controller from the cluster, run:
```shell
make undeploy
```

To remove the custom resource definitions (CRDs) for the cert-manager external issuer for Keyfactor command, run:
```shell
make uninstall
```