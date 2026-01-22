# Ambient Credentials with Google Kubernetes Engine (GKE)

> **IMPORTANT**: Support for adding Google as an identity provider in Command is only officially supported with Keyfactor Command 25.1.2+ and 25.2.1+. If you are on an older version of Command, please contact Keyfactor Customer Support for assistance on adding Google as an identity provider.

This documentation covers the various ways to configure GKE workload identity for your workload to use ambient credentials with Keyfactor Command. Please refer to the official [Google documentation for workload identity federation](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) for the most up-to-date information regarding workload identity with GKE. For more information about what workload identity is and how it works in GKE, please refer [here](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity).

## Authentication Options Overview

GKE workloads can authenticate to external services like Keyfactor Command by obtaining ID tokens from the GKE metadata server. There are two approaches to configure this:

1. **Workload Identity Federation for GKE with Service Account Impersonation** (Recommended) - Kubernetes ServiceAccounts are bound to Google Service Accounts, allowing fine-grained, per-workload identity management. The GKE metadata server uses the bound Google Service Account to generate ID tokens.
2. **Compute Engine Default Service Account** (Not recommended for production) - Workloads use a shared node-level service account; all workloads on the same node inherit these credentials with no isolation.

This guide covers both approaches, but ***Workload Identity Federation for GKE with Service Account Impersonation is the recommended method*** for new deployments due to its improved security model and workload isolation.

> **Important**: For the GKE metadata server to generate ID tokens, a Google Service Account must be available. In Option 1, you explicitly create and bind a GSA to your Kubernetes ServiceAccount. In Option 2, the Compute Engine default service account is used implicitly.

> For more information on alternatives to Workload Identity Federation for GKE (and security compromises associated with these alternatives), please refer [to this list](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity). 

> For more information about service accounts in GKE, please refer to [this link](https://cloud.google.com/kubernetes-engine/docs/how-to/service-accounts).

## Prerequisites

Before configuring ambient credentials with GKE, ensure you have met the requirements [specified in Google's GKE guide](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) in addition to the following:

- A GKE cluster (version 1.12 or later recommended; 1.24+ for all Workload Identity Federation features)
- `gcloud` CLI installed and authenticated
- `kubectl` configured to access your cluster
- Appropriate IAM permissions:
  - `roles/container.admin` (for cluster configuration)
  - `roles/iam.serviceAccountAdmin` (for service account management)
  - `roles/iam.securityAdmin` (for IAM policy binding)
- Keyfactor Command 25.1.2+ or 25.2.1+ with Google OIDC provider configured ([how to configure](#configuring-google-as-identity-provider-in-keyfactor-command))

## GKE Identity Configuration Options

### Option 1: Workload Identity Federation for GKE with Service Account Impersonation (Recommended)

Workload Identity Federation for GKE with Service Account impersonation is the **most secure** method to grant your workloads the ability to obtain ID tokens for authentication. This approach:

1. Creates a Google Service Account (GSA) specifically for your workload
2. Binds your Kubernetes ServiceAccount (KSA) to the GSA through IAM policy
3. Annotates the KSA to indicate which GSA to use
4. Allows the GKE metadata server to generate ID tokens using the GSA's identity

#### Why Service Account Impersonation is Required

The GKE metadata server endpoint (`metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity`) requires a Google Service Account to generate ID tokens. Without a GSA bound to your KSA:
- The metadata server has no identity to issue tokens for
- Token generation requests will fail with "service account not defined" errors
- Your workload cannot authenticate to external services

The KSA annotation (`iam.gke.io/gcp-service-account`) tells the metadata server which GSA to use when generating tokens for pods using that KSA.

#### Advantages
- **Better Security**: Fine-grained, per-workload identity without shared credentials
- **Workload Isolation**: Each workload can have its own dedicated GSA with specific permissions
- **Audit Trail**: Clear mapping between Kubernetes workloads and Google Service Accounts
- **Principle of Least Privilege**: Grant only the minimum required permissions to each workload

#### Setup

For the below steps, configure your environment variables.

```bash
# Get project-level metadata
export PROJECT_ID=$(gcloud config get project) # use "gcloud projects list" to get a list of projects and "gcloud config set project <PROJECT_ID>" to set the project
export PROJECT_NUMBER=$(gcloud projects describe ${PROJECT_ID} \
  --format="value(projectNumber)")

export CLUSTER_NAME="cluster-name-here" # The name of your GKE cluster
export REGION="cluster-region" # The region your GKE cluster is deployed to (i.e. us-east1)

export DEPLOYMENT_NAME="command-issuer" # The Helm chart deployment name
export KSA_NAMESPACE="command-issuer-system" # The namespace your command-cert-manager-issuer is deployed to (change if different than defined in root README) 
export KSA_NAME="command-issuer" # This is the Kubernetes ServiceAccount that is automatically created when command-cert-manager-issuer is deployed with Helm
export GSA_NAME="command-cert-manager-issuer-gsa" # Google Service Account that will be created to grant the KSA permissions to assume its identity

export NODEPOOL_NAME="gke-wi-nodepool" # The nodepool that will have the GKE metadata server enabled on it
```

#### Step 1: Enable Workload Identity Federation on Your Cluster

For **existing clusters**, enable Workload Identity Federation:

```bash
# Enable Workload Identity Federation on the cluster
gcloud container clusters update ${CLUSTER_NAME} \
--location=${REGION} \
--workload-pool=${PROJECT_ID}.svc.id.goog
```

For **new clusters**, create with Workload Identity Federation enabled:

```bash
# Create cluster with Workload Identity Federation
gcloud container clusters create ${CLUSTER_NAME} \
--region=${REGION} \
--workload-pool=${PROJECT_ID}.svc.id.goog
```

> **Note**: If your cluster was created after May 30, 2024 (Standard) or June 18, 2024 (Autopilot), Workload Identity is enabled by default. You can verify this with:
> ```bash
> gcloud container clusters describe ${CLUSTER_NAME} \
>   --location=${REGION} \
>   --format="value(workloadIdentityConfig.workloadPool)"
> ```

#### Step 2: Configure Node Pools (if needed)

Check if your node pools have the GKE metadata server enabled:

```bash
# Check the workload metadata configuration
gcloud container node-pools describe  \
  --cluster=${CLUSTER_NAME} \
  --location=${REGION} \
  --format="value(config.workloadMetadataConfig.mode)"
```

If the output is `GKE_METADATA`, you can skip this step. If it's `GCE_METADATA` or empty, create a new node pool or update existing pools:

```bash
# Option A: Create a new node pool with GKE_METADATA
gcloud container node-pools create ${NODEPOOL_NAME} \
  --cluster=${CLUSTER_NAME} \
  --location=${REGION} \
  --workload-metadata=GKE_METADATA

# Option B: Update existing node pool (requires recreation of nodes)
gcloud container node-pools update  \
  --cluster=${CLUSTER_NAME} \
  --location=${REGION} \
  --workload-metadata=GKE_METADATA
```

> **Note**: Clusters created after the dates mentioned in Step 1 have `GKE_METADATA` enabled by default on all node pools.

#### Step 3: Create Google Service Account

Create a Google Service Account that will be used to generate ID tokens:

```bash
# Create the Google Service Account
gcloud iam service-accounts create ${GSA_NAME} \
  --display-name="command-cert-manager-issuer Service Account" \
  --project=${PROJECT_ID}
```

> **Important**: This GSA doesn't need any GCP API permissions unless your workload needs to access other Google Cloud services. For ID token generation alone, the service account just needs to exist.

#### Step 4: Create Kubernetes Namespace and ServiceAccount

```bash
# Get cluster credentials
gcloud container clusters get-credentials ${CLUSTER_NAME} \
  --region=${REGION}

# Create namespace if it doesn't already exist
kubectl create namespace ${KSA_NAMESPACE} 2>/dev/null || true

# Create Kubernetes ServiceAccount if it doesn't already exist
kubectl create serviceaccount ${KSA_NAME} \
  --namespace=${KSA_NAMESPACE} 2>/dev/null || true
```

#### Step 5: Create Workload Identity Binding

Bind the Kubernetes ServiceAccount to the Google Service Account, allowing the KSA to impersonate the GSA:

```bash
# Allow the KSA to impersonate the GSA
gcloud iam service-accounts add-iam-policy-binding ${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
  --role roles/iam.workloadIdentityUser \
  --member "serviceAccount:${PROJECT_ID}.svc.id.goog[${KSA_NAMESPACE}/${KSA_NAME}]"
```

This grants the `roles/iam.workloadIdentityUser` role to the Kubernetes ServiceAccount, allowing it to act as the Google Service Account.

#### Step 6: Annotate Kubernetes ServiceAccount

Annotate the KSA to specify which GSA it should use:

```bash
# Annotate the KSA with the GSA email
kubectl annotate serviceaccount ${KSA_NAME} \
  --namespace ${KSA_NAMESPACE} \
  iam.gke.io/gcp-service-account=${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com
```

This annotation is **critical** - it tells the GKE metadata server which Google Service Account to use when generating ID tokens for pods using this KSA.

#### Step 7: Update Workload to Use GKE Metadata Server Nodes (if needed)

If you created a new node pool with `GKE_METADATA` enabled, update your deployment to schedule pods on those nodes:

If `command-cert-manager-issuer` was deployed using Helm:

```bash
helm upgrade ${DEPLOYMENT_NAME} deploy/charts/command-cert-manager-issuer \
  --namespace ${KSA_NAMESPACE} \
  --reuse-values \
  --set-string "nodeSelector.iam\.gke\.io/gke-metadata-server-enabled=true"
```

If deployed without Helm, edit the Deployment directly:

```bash
kubectl edit deployment ${DEPLOYMENT_NAME} -n ${KSA_NAMESPACE}
```

Add the nodeSelector under `spec.template.spec`:

```yaml
spec:
  template:
    spec:
      nodeSelector:
        iam.gke.io/gke-metadata-server-enabled: "true"
```

Then restart the deployment:

```bash
kubectl rollout restart deployment ${DEPLOYMENT_NAME} -n ${KSA_NAMESPACE}
```

> **Note**: If all your node pools have `GKE_METADATA` enabled, you can skip the nodeSelector configuration.

#### Step 8: Retrieve Identity Information for Keyfactor Command

Get the OAuth Client ID (unique ID) of the Google Service Account:

```bash
gcloud iam service-accounts describe ${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com \
    --format="value(oauth2ClientId)"
```

This ID will be used to create a security claim in Keyfactor Command for your identity provider.

---

### Option 2: Compute Engine Default Service Account (Not Recommended for Production)

> **SECURITY WARNING**: All pods on the same node share the same service account, which violates the principle of least privilege. This approach is provided for reference only and is **strongly discouraged** for production use.

When creating a GKE cluster without specifying a custom service account, nodes automatically use the Compute Engine [default service account](https://cloud.google.com/compute/docs/access/service-accounts#token) (`<project-number>-compute@developer.gserviceaccount.com`). This service account can be used by the GKE metadata server to generate ID tokens.

#### Security Concerns

- By default, the Compute Engine service account has the Editor role, which is overly permissive
- All pods on the same node share this identity with no isolation
- No per-workload credential management
- Violates the principle of least privilege
- Increases blast radius in case of pod compromise
- Cannot distinguish between different workloads in audit logs

**For production environments, use Option 1 instead.**

For the below steps, configure your environment variables:

```bash
# Get project-level metadata
export PROJECT_ID=$(gcloud config get project) # use "gcloud projects list" to get a list of projects and "gcloud config set project <PROJECT_ID>" to set the project
export PROJECT_NUMBER=$(gcloud projects describe ${PROJECT_ID} \
  --format="value(projectNumber)")

export CLUSTER_NAME="cluster-name-here" # The name of your GKE cluster
export REGION="cluster-region" # The region your GKE cluster is deployed to (i.e. us-east1)
```

#### Step 1: Check Current Configuration

Verify that your cluster is using the default node service account:

```bash
# Check if Workload Identity Federation is enabled
gcloud container clusters describe ${CLUSTER_NAME} \
  --region=${REGION} \
  --format="value(workloadIdentityConfig.workloadPool)"

# If empty, Workload Identity Federation is NOT enabled

# Check node pool service account
gcloud container node-pools describe default-pool \
  --cluster=${CLUSTER_NAME} \
  --region=${REGION} \
  --format="value(config.serviceAccount)"

# If "default", you're using the Compute Engine default service account
```

#### Step 2: Retrieve Identity Information

Get the OAuth Client ID (unique ID) of the Compute Engine default service account:

```bash
# Get the unique ID (sub claim)
gcloud iam service-accounts describe \
  ${PROJECT_NUMBER}-compute@developer.gserviceaccount.com \
  --format='value(oauth2ClientId)'
```

This ID will be used to create a security claim in Keyfactor Command for your identity provider.

## Configuring Google as Identity Provider in Keyfactor Command

After configuring your GKE workload identity, you need to set up Google as an identity provider in Keyfactor Command.

### Step 1: Navigate to Identity Providers

1. Log in to Keyfactor Command
2. Navigate to **Settings** > **Identity Providers**
3. Click **Add**

### Step 2: Import Discovery Document

Use Google's standard OIDC discovery endpoint:

```
https://accounts.google.com/.well-known/openid-configuration
```

This endpoint provides the necessary configuration for Google's identity provider, including the issuer URL, token endpoints, and supported claims.

### Step 3: Configure Claim Mappings

Configure the following claim mappings:

- **Name Claim Type** (OAuth Subject): `sub`
- **Unique Claim Type** (OAuth Object ID): `azp` (or `sub`, depending on your token format)
- **Display Name**: Google GKE (or your preferred name)

> **Note**: For programmatic API access, Command requires you to fill in Client ID and Client Secret fields, but these values are not actually used for workload identity authentication. You can use any placeholder values for these fields.

### Step 4: Save and Test

1. Click **Save** to create the identity provider
2. Test the configuration by retrieving a token from your workload
3. Verify the token is accepted by Keyfactor Command

### Step 5: Map Identity to Security Roles

After saving the identity provider:

1. Navigate to **Security** > **Security Roles**
2. Select or create a security role for your workload
3. Add a security claim with the appropriate identifier:
   - For **Option 1 (Workload Identity with SA impersonation)**: Use the OAuth Client ID of your Google Service Account (from Step 8 above)
   - For **Option 2 (Compute Engine default SA)**: Use the OAuth Client ID of the Compute Engine default service account
4. Configure the appropriate permissions for certificate operations

The security claim format in Command should be:
- **Claim Type**: OAuth Subject (or similar, depending on your token's `sub` claim)
- **Claim Value**: The numeric OAuth Client ID retrieved in the setup steps

---

## Troubleshooting

### Common Issues

> For any issues not covered below, check out the [root README's troubleshooting](../../README.md#troubleshooting) section.

#### Issue: "metadata: GCE metadata 'instance/service-accounts/default/identity' not defined"

**Cause**: The KSA annotation is missing or incorrect, or the workload identity binding is not configured

**Solution**: 
1. Verify the KSA annotation exists:
   ```bash
   kubectl get serviceaccount ${KSA_NAME} -n ${KSA_NAMESPACE} -o yaml | grep iam.gke.io/gcp-service-account
   ```
2. Verify the workload identity binding:
   ```bash
   gcloud iam service-accounts get-iam-policy ${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com
   ```
3. Ensure pods are restarted after adding the annotation:
   ```bash
   kubectl rollout restart deployment ${DEPLOYMENT_NAME} -n ${KSA_NAMESPACE}
   ```

#### Issue: "Permission denied" errors

**Cause**: IAM permissions not correctly configured

**Solution**: 
- Verify the workload identity binding is correct:
  ```bash
  gcloud iam service-accounts get-iam-policy ${GSA_NAME}@${PROJECT_ID}.iam.gserviceaccount.com
  ```
- Ensure the binding includes `roles/iam.workloadIdentityUser` for the correct KSA
- Check that the workload pool is correctly configured on the cluster

#### Issue: "Invalid token" from Keyfactor Command

**Cause**: Issuer URL mismatch or incorrect claim mapping

**Solution**:
- Verify the issuer URL in Keyfactor matches the token's `iss` claim (`https://accounts.google.com`)
- Check that the security claim in Keyfactor Command matches the token's `sub` claim (should be the OAuth Client ID)
- Ensure the token audience matches what Keyfactor Command expects
- Verify the identity provider discovery document was imported correctly

#### Issue: Pod cannot authenticate / Workload Identity not working

**Cause**: Workload Identity not enabled on cluster or node pool metadata incorrect

**Solution**:
```bash
# Verify Workload Identity is enabled on cluster
gcloud container clusters describe ${CLUSTER_NAME} \
  --location=${REGION} \
  --format="value(workloadIdentityConfig.workloadPool)"

# Should output: .svc.id.goog

# Check node pool metadata configuration
gcloud container node-pools describe  \
  --cluster=${CLUSTER_NAME} \
  --location=${REGION} \
  --format="value(config.workloadMetadataConfig.mode)"

# Should output: GKE_METADATA

# If not correct, update the cluster:
gcloud container clusters update ${CLUSTER_NAME} \
  --location=${REGION} \
  --workload-pool=${PROJECT_ID}.svc.id.goog

# And update/create node pool:
gcloud container node-pools create ${NODEPOOL_NAME} \
  --cluster=${CLUSTER_NAME} \
  --location=${REGION} \
  --workload-metadata=GKE_METADATA
```

---

## Additional Resources

- [Official GKE Workload Identity Documentation](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity)
- [Workload Identity Federation Concepts](https://cloud.google.com/kubernetes-engine/docs/concepts/workload-identity)
- [Supported Products and Limitations](https://cloud.google.com/iam/docs/federated-identity-supported-services)
- [Keyfactor Command Identity Provider Documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/IdentityProviderOperations.htm)
- [Google Service Account Documentation](https://cloud.google.com/iam/docs/service-account-overview)
- [Best Practices for GKE Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#best_practices)
