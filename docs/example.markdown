<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Demo ClusterIssuer Usage with K8s Ingress

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/command-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/command-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

### Documentation Tree
* [Installation](install.markdown)
* [Usage](config_usage.markdown)
* [Customization](annotations.markdown)
* [Testing the Source](testing.markdown)

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