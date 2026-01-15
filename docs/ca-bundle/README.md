# CA Bundle

The command-cert-manager-issuer integration requires a secure, trusted connection with the targeted Keyfactor Command instance.

## Using Self-Signed Certificates

If the targeted Keyfactor Command API is configured to use a self-signed certificate or with a certificate whose issuer isn't widely trusted, the CA certificate **must be provided** as a Kubernetes secret. The secret must belong to the same namespace that command-cert-manager-issuer is deployed to. 

```shell
kubectl -n command-issuer-system create secret generic command-ca-secret --from-file=ca.crt
```

In the issuer specification, reference the created secret with the `caSecretName` field. The issuer resource does not need to belong to the same namespace as the secret.

```yaml
 apiVersion: command-issuer.keyfactor.com/v1alpha1
 kind: Issuer
 metadata:
   name: issuer-sample
   namespace: default
 spec:
   ...
   caSecretName: "command-ca-secret"
```

## Using Publicly Trusted Certificates

If the targeted Keyfactor Command API is configured with a publicly trusted certificate authority (Sectigo / LetsEncrypt / etc.), the command-cert-manager-issuer image is built with a pre-bundled trust store of publicly trusted certificates but with a ***very important caveat***. The trust store may become out-of-sync over time, especially if the certificate authority issuing the Keyfactor Command certificate is updated.

It is not required to use the `caSecretName` specification, but it is **recommended** to maintain a list of trusted certificates instead of relying on the pre-bundled certificate store when the command-cert-manager-issuer image is created. This will reduce the likelihood of connectivity issues if the Keyfactor Command instance is updated to use a new CA or if the command-cert-manager-issuer image is updated and it does not include the Command CA in its trust store.

### trust-manager

[trust-manager](https://cert-manager.io/docs/trust/trust-manager/) can be used to sync CA trust bundles in a Kubernetes cluster. trust-manager can synchronize a list of publicly trusted CAs as well as any custom CAs to be included in the trust chain.

#### Pre-requisites

- cert-manager is already installed in the Kubernetes cluster
- a namespace is already created where trust-manager will sync CA bundles to (i.e. command-issuer-system)

#### Security Considerations

> ⚠️ Important: Required Permissions

trust-manager requires **cluster-wide read access** to secrets. This is a hard technical requirement of trust-manager's architecture.

| Permission Type | Scope              | Resources           | Verbs                         | Purpose                           |
| --------------- | ------------------ | ------------------- | ----------------------------- | --------------------------------- |
| **Read**        | Cluster-wide       | secrets, configmaps | get, list, watch              | Discover sources, monitor targets |
| **Write**       | Namespace-specific | secrets             | create, update, patch, delete | Deploy CA bundles                 |

#### Setting up trust-manager

1. Install trust-manager

    Please refer to the [trust-manager installation documentation](https://cert-manager.io/docs/trust/  trust-manager/installation/) for up-to-date installation instructions.

    ```bash
    # Install trust-manager in the cert-manager namespace
    helm install trust-manager oci://quay.io/jetstack/charts/trust-manager \
      --namespace cert-manager \
      --set secretTargets.enabled=true \
      --create-namespace \
      --wait
    ```
2. Create a Secret from a PEM file

   Create a secret containing the PEM of the CA certificates you want to trust. Create the secret in the same namespace trust-manager is deployed to.

   ```bash
   kubectl create secret generic enterprise-root-ca \
        --from-file=ca.crt=/path/to/root-ca.pem \
        --namespace=cert-manager \
        --dry-run=client -o yaml | kubectl apply -f -
   ```

3a. Create a ClusterRole for trust-manager

   This RBAC policy gives trust-manager read permission to secrets across the entire cluster

   ```yaml
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      name: trust-manager-read
      labels:
        app.kubernetes.io/name: trust-manager
    rules:
    - apiGroups: ["trust.cert-manager.io"]
      resources: ["bundles"]
      verbs: ["get", "list", "watch"]
    - apiGroups: ["trust.cert-manager.io"]
      resources: ["bundles/status"]
      verbs: ["patch", "update"]
    - apiGroups: [""]
      resources: ["secrets", "configmaps"]
      verbs: ["get", "list", "watch"]
    - apiGroups: [""]
      resources: ["namespaces"]
      verbs: ["get", "list", "watch"]
    - apiGroups: [""]
      resources: ["events"]
      verbs: ["create", "patch"]

    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: trust-manager-read
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: trust-manager-read
    subjects:
    - kind: ServiceAccount
      name: trust-manager
      namespace: cert-manager
   ```
3b. Create a namepaced Role for trust-manager

    For each namespace that trust-manager should sync secrets to, create a role that allows trust-manager to write secrets

    ```yaml
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: trust-manager-write
      namespace: command-issuer-system  # change to your namespace
    rules:
    - apiGroups: [""]
      resources: ["secrets"]
        verbs: ["create", "update", "patch", "delete"]

    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: RoleBinding
    metadata:
      name: trust-manager-write
      namespace: command-issuer-system  # change to your namespace
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: Role
      name: trust-manager-write
    subjects:
    - kind: ServiceAccount
      name: trust-manager
      namespace: cert-manager
    ```
4. Label target namespaces

    Label the namespace command-cert-manager-issuer is deployed to annotate trust-manager should write secrets to it

    ```bash
    kubectl label namespace command-issuer-system command-issuer-ca-bundle=enabled # change to your namespace
    ```

5. Create a Bundle

    Create a bundle resource to tell trust-manager what secrets to synchronize and whether to include publicly trusted CAs as part of the sync.

    ```yaml
    apiVersion: trust.cert-manager.io/v1alpha1
    kind: Bundle
    metadata:
      name: command-issuer-ca-bundle
    spec:
      sources:
      - useDefaultCAs: true # determines whether to bundle publicly trusted certificates used to    validate most TLS certificates on the internet (Let's Encrypt, Google, Amazon, etc.)
    
      - secret:
          name: "enterprise-root-ca"
          key: "ca.crt"

      # Additional intermediate or partner CAs
      #- secret:
      #    name: "enterprise-ca-bundle"
      #    key: "ca.crt"
    
      target:
        secret:
          key: "ca.crt"

        # Distribute to all namespaces with this label
        namespaceSelector:
          matchLabels:
            command-issuer-ca-bundle: "enabled"
    ```

#### Using the trust bundle

Once the setup is complete, a secret called `command-issuer-ca-bundle` will appear in the desired namespace (i.e. `command-issuer-system`) and the trusted CA bundle will appear in the `ca.crt` key.

In your issuer specification (Issuer/ClusterIssuer), reference the secret in the `caSecretName` specification field:

```yaml
 apiVersion: command-issuer.keyfactor.com/v1alpha1
 kind: Issuer # or ClusterIssuer
 metadata:
   ...
 spec:
   ...
   caSecretName: "command-issuer-ca-bundle"
```