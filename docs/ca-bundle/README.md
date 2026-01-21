# CA Bundle

The command-cert-manager-issuer integration requires a secure, trusted connection with the targeted Keyfactor Command instance.

## Using Self-Signed Certificates

If the targeted Keyfactor Command API is configured to use a self-signed certificate or with a certificate whose issuer isn't widely trusted, the CA certificate **must be provided** via a Kubernetes Secret of ConfigMap. The secret must belong to the same namespace that command-cert-manager-issuer is deployed to (i.e. `command-issuer-system`). 

```shell
kubectl -n command-issuer-system create secret generic command-ca-secret --from-file=ca.crt

kubectl -n command-issuer-system create configmap command-ca --from-file=ca.crt
```

In the Issuer / ClusterIssuer specification, reference the created resource.

```yaml
 apiVersion: command-issuer.keyfactor.com/v1alpha1
 kind: Issuer
 metadata:
   name: issuer-sample
   namespace: default
 spec:
   ...
   caSecretName: "command-ca-secret" # if using Kubernetes Secret
   caBundleConfigMapName: "command-ca" # if using Kubernetes ConfigMap
   caBundleKey: "ca.crt" # optional key name, pulls the last key in resource if not specified
```

## Using Publicly Trusted Certificates

If the targeted Keyfactor Command API is configured with a publicly trusted certificate authority (Sectigo / LetsEncrypt / etc.), the command-cert-manager-issuer container image is built with a pre-bundled trust store of publicly trusted certificates but with a ***very important caveat***. The trust store may become out-of-sync over time, especially if the certificate authority issuing the Keyfactor Command certificate is updated.

It is **not required** to use the `caSecretName` / `caBundleConfigMapName` specification if Keyfactor Command's TLS certificate is built using a publicly trusted root, but it is **recommended for production workloads to maintain a list of trusted certificates** instead of relying on the pre-bundled certificate store when the command-cert-manager-issuer image is created. This will reduce the likelihood of connectivity issues if the Keyfactor Command instance is updated to use a new CA or if the command-cert-manager-issuer image is updated and it does not include the Keyfactor Command TLS certificate's root CA in its trust store.

This document covers available tools to help manage CA trust bundles.

### trust-manager

[trust-manager](https://cert-manager.io/docs/trust/trust-manager/) can be used to sync CA trust bundles in a Kubernetes cluster. trust-manager can synchronize a list of publicly trusted CAs as well as any custom CAs to be included in the trust chain. It is recommended to add your Keyfactor Command's intermediate and root CAs to a Kubernetes Secret / ConfigMap and synchronize this with the trust-manager bundle.

The publicly trusted certificates are tied to the trust-manager image. To pull up-to-date publicly trusted CAs, update the trust-manager deployment to the latest version.

trust-manager can synchronize the CA trust bundle to either a Kubernetes Secret or ConfigMap, this documentation will cover both methods.

> NOTE: For the latest documentation and installation instructions, please refer to the [cert-manager trust-manager documentation](https://cert-manager.io/docs/trust/trust-manager/installation/). The instructions below may become outdated over time.

#### Pre-requisites

- cert-manager is already installed in the Kubernetes cluster
- a namespace is already created where trust-manager will sync CA bundles to (i.e. command-issuer-system)

#### Security Considerations

> ⚠️ Important: Required Permissions. Please Read!

trust-manager requires different permission scopes depending on your synchronization target:

**Synchronizing to ConfigMaps (Recommended):**
- ✅ Only requires cluster-wide **read** access to ConfigMaps
- ✅ Lower security risk
- ✅ Suitable for most environments

**Synchronizing to Secrets:**
- ⚠️ Requires cluster-wide **read** access to **all Secrets**
- ⚠️ Higher security risk - trust-manager can read any secret in the cluster
- ⚠️ Requires explicit RBAC configuration (shown below)
- ⚠️ Only use if you have specific requirements for Secret storage

**Permission Summary:**

| Target Type | Read Scope     | Write Scope        | Security Impact |
|-------------|----------------|--------------------|-----------------| 
| ConfigMap   | ConfigMaps     | Namespace-specific | Low             |
| Secret      | **All Secrets**| Namespace-specific | High            |

For most deployments, **Option 1 (ConfigMap)** is recommended unless you have compliance requirements mandating Secret storage.

#### Option 1: Synchronizing to a ConfigMap

##### Setting up trust-manager

1. Install trust-manager

    ```bash
    # Install trust-manager in the cert-manager namespace
    helm install trust-manager oci://quay.io/jetstack/charts/trust-manager \
      --namespace cert-manager \
      --create-namespace \
      --wait
    ```
2. Create a ConfigMap from a PEM file

   Create a ConfigMap containing the PEM of the CA certificates you want to trust. Create the ConfigMap in the same namespace trust-manager is deployed to.

   ```bash
   kubectl create configmap enterprise-root-ca \
        --from-file=ca.crt=/path/to/root-ca.pem \
        --namespace=cert-manager \
        --dry-run=client -o yaml | kubectl apply -f -
   ```

3. Label target namespaces

    Label the namespace command-cert-manager-issuer is deployed to annotate trust-manager should write ConfigMaps to it

    ```bash
    kubectl label namespace command-issuer-system command-issuer-ca-bundle=enabled # change to your namespace
    ```

4. Create a Bundle

    Create a bundle resource to tell trust-manager what ConfigMaps to synchronize and whether to include publicly trusted CAs as part of the sync.

    ```yaml
    kubectl apply -f - <<EOF
    apiVersion: trust.cert-manager.io/v1alpha1
    kind: Bundle
    metadata:
      name: command-issuer-ca-bundle
    spec:
      sources:
      - useDefaultCAs: true # determines whether to bundle publicly trusted certificates used to validate most TLS certificates on the internet (Let's Encrypt, Google, Amazon, etc.)
    
      - configMap:
          name: "enterprise-root-ca"
          key: "ca.crt"

      # Additional intermediate or partner CAs (can also target Secrets in the same namespace)
      #- secret:
      #    name: "enterprise-ca-bundle"
      #    key: "ca.crt"
    
      target:
        configMap:
          key: "ca.crt"

        # Distribute to all namespaces with this label
        namespaceSelector:
          matchLabels:
            command-issuer-ca-bundle: "enabled"
      EOF
    ```

##### Using the trust bundle

Once the setup is complete, trust-manager will create a resource in the target namespace:
- **Resource name:** Matches the Bundle metadata name (`command-issuer-ca-bundle` in this example)
- **Namespace:** Any namespace matching the `namespaceSelector` label
- **Key:** As specified in `target.configMap.key`

You can verify the resource was created:
````bash
kubectl get configmap -n command-issuer-system command-issuer-ca-bundle
````

In your issuer specification (Issuer/ClusterIssuer), reference the ConfigMap in the `caBundleConfigMapName` specification field:

```yaml
 apiVersion: command-issuer.keyfactor.com/v1alpha1
 kind: Issuer # or ClusterIssuer
 metadata:
   ...
 spec:
   ...
   caBundleConfigMapName: "command-issuer-ca-bundle"
   caBundleKey: "ca.crt" # optional key name, pulls the last key in resource if not specified
```

#### Option 2: Synchronizing to a Secret

##### Setting up trust-manager

1. Install trust-manager

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

3. Label target namespaces

    Label the namespace command-cert-manager-issuer is deployed to annotate trust-manager should write secrets to it

    ```bash
    kubectl label namespace command-issuer-system command-issuer-ca-bundle=enabled # change to your namespace
    ```

4. Configure RBAC policies for trust-manager

Due to Kubernetes constraints, writing to secrets outside of trust-manager's namespace is forbidden unless explicit policy is provided. trust-manager needs cluster-level access to read secrets, so a ClusterRole RBAC policy must be created to grant cluster-level read secret access to trust-manager

4a. Create a ClusterRole for trust-manager

   This RBAC policy gives trust-manager read permission to secrets across the entire cluster

   ```yaml
    kubectl apply -f - <<EOF
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRole
    metadata:
      name: trust-manager-read-secrets
      labels:
        app.kubernetes.io/name: trust-manager
    rules:
    - apiGroups: [""]
      resources: ["secrets"]
      verbs: ["get", "list", "watch"]

    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: ClusterRoleBinding
    metadata:
      name: trust-manager-read-secrets
    roleRef:
      apiGroup: rbac.authorization.k8s.io
      kind: ClusterRole
      name: trust-manager-read-secrets
    subjects:
    - kind: ServiceAccount
      name: trust-manager
      namespace: cert-manager
    EOF
   ```

4b. Create a namepaced Role for trust-manager

  For each namespace that trust-manager should sync secrets to, create a role that allows trust-manager to write secrets

    ```yaml
    kubectl apply -f - <<EOF
    ---
    apiVersion: rbac.authorization.k8s.io/v1
    kind: Role
    metadata:
      name: trust-manager-write
      namespace: command-issuer-system  # change to your namespace
    rules:
    - apiGroups: [""]
      resources: ["secrets"]
      verbs: ["create", "update", "patch", "delete", "read"]
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

5. Create a Bundle

    Create a bundle resource to tell trust-manager what secrets to synchronize and whether to include publicly trusted CAs as part of the sync.

    ```yaml
    kubectl apply -f - <<EOF
    apiVersion: trust.cert-manager.io/v1alpha1
    kind: Bundle
    metadata:
      name: command-issuer-ca-bundle
    spec:
      sources:
      - useDefaultCAs: true # determines whether to bundle publicly trusted certificates used to validate most TLS certificates on the internet (Let's Encrypt, Google, Amazon, etc.)
    
      - secret:
          name: "enterprise-root-ca"
          key: "ca.crt"

      # Additional intermediate or partner CAs (can also target ConfigMaps in the same namespace)
      #- configMap:
      #    name: "enterprise-ca-bundle"
      #    key: "ca.crt"
    
      target:
        secret:
          key: "ca.crt"

        # Distribute to all namespaces with this label
        namespaceSelector:
          matchLabels:
            command-issuer-ca-bundle: "enabled"
      EOF
    ```

##### Using the trust bundle

Once the setup is complete, trust-manager will create a resource in the target namespace:
- **Resource name:** Matches the Bundle metadata name (`command-issuer-ca-bundle` in this example)
- **Namespace:** Any namespace matching the `namespaceSelector` label
- **Key:** As specified in `target.secret.key`

You can verify the resource was created:
````bash
kubectl get secret -n command-issuer-system command-issuer-ca-bundle
````

In your issuer specification (Issuer/ClusterIssuer), reference the secret in the `caSecretName` specification field:

```yaml
 apiVersion: command-issuer.keyfactor.com/v1alpha1
 kind: Issuer # or ClusterIssuer
 metadata:
   ...
 spec:
   ...
   caSecretName: "command-issuer-ca-bundle"
   caBundleKey: "ca.crt" # optional key name, pulls the last key in resource if not specified
```