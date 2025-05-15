<h1 align="center" style="border-bottom: none">
    Command Issuer
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/command-cert-manager-issuer/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/command-cert-manager-issuer?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/command-cert-manager-issuer?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/command-cert-manager-issuer/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a> 
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/topics/keyfactor-integration">
    <b>Related Integrations</b>
  </a>
</p>

## Support
The Command Issuer is open source and community supported, meaning that there is **no SLA** applicable. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.


# Overview

The Command Issuer for [cert-manager](https://cert-manager.io/) is a [CertificateRequest](https://cert-manager.io/docs/usage/certificaterequest/) controller that issues certificates using [Keyfactor Command](https://www.keyfactor.com/products/command/).

# Requirements

Before continuing, ensure that the following requirements are met:

- [Keyfactor Command](https://www.keyfactor.com/products/command/) >= 10.5
    - Command must be properly configured according to the [product docs](https://software.keyfactor.com/Core-OnPrem/Current/Content/MasterTopics/Portal.htm). 
    - You have access to the Command REST API. The following endpoints must be available:
        - `/Status/Endpoints`
        - `/Enrollment/CSR`
        - `/MetadataFields`
- Kubernetes >= v1.19
    - [Kubernetes](https://kubernetes.io/docs/tasks/tools/), [Minikube](https://minikube.sigs.k8s.io/docs/start/), [Kind](https://kind.sigs.k8s.io/docs/user/quick-start/), etc.
    > You must have permission to create [Custom Resource Definitions](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/) in your Kubernetes cluster.
- [Supported cert-manager release](https://cert-manager.io/docs/releases/) installed in your cluster. Please see the [cert-manager installation](https://cert-manager.io/docs/installation/) for details.
- [Supported version of Helm](https://helm.sh/docs/topics/version_skew/) for your Kubernetes version

# Getting Started

## Configuring Command

Command Issuer enrolls certificates by submitting a POST request to the Command CSR Enrollment endpoint. Before using Command Issuer, you must create or identify a Certificate Authority _and_ Certificate Template suitable for your usecase. Additionally, you should ensure that the identity used by the Issuer/ClusterIssuer has the appropriate permissions in Command.

1. **Create or identify a Certificate Authority**

    A certificate authority (CA) is an entity that issues digital certificates. Within Keyfactor Command, a CA may be a Microsoft CA, EJBCA, or a Keyfactor gateway to a cloud-based or remote CA.

    - If you haven't created a Certificate Authority before, refer to the [Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/CA-Operations.htm) to learn how, or reach out to your Keyfactor support representative.

    The CA that you choose must be configured to allow CSR Enrollment.

2. **Identify a Certificate Template**

    Certificate Templates in Command define properties and constraints of the certificates being issued. This includes settings like key usage, extended key usage, validity period, allowed key algorithms, and signature algorithms. They also control the type of information that end entities must provide and how that information is validated before issuing certificates.

    - If you don't have any suitable Certificate Templates, refer to the [Command documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Configuring%20Template%20Options.htm?Highlight=Certificate%20Template) or reach out to your Keyfactor support representative to learn more.

    The Certificate Template that you choose must be configured to allow CSR Enrollment.

    You should make careful note of the allowed Key Types and Key Sizes on the Certificate Template. When creating cert-manager [Certificates](https://cert-manager.io/docs/usage/certificate/), you must make sure that the key `algorithm` and `size` are allowed by your Certificate Template in Command.    

    The same goes for **Enrollment RegExes** and **Policies** defined on your Certificate Template. When creating cert-manager [Certificates](https://cert-manager.io/docs/usage/certificate/), you must make sure that the `subject`, `commonName`, `dnsNames`, etc. are allowed and/or configured correctly by your Certificate Template in Command.

3. **Configure Command Security Roles and Claims**

    In Command, Security Roles define groups of users or administrators with specific permissions. Users and subjects are identified by Claims. By adding a Claim to a Security Role, you can define what actions the user or subject can perform and what parts of the system it can interact with.

    The security role will need to be added as an Allowed Requester Security Role on the Certificate Authority and Certificate Template configured in the previous two steps.

    - If you haven't created Roles and Access rules before, [this guide](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SecurityOverview.htm?Highlight=Security%20Roles) provides a primer on these concepts in Command.

    If your security policy requires fine-grain access control, Command Issuer requires the following Access Rules:

    | Global Permissions                    | Permission Model (Version Two) | Permission Model (Version One) |
    |-----------------------------------------|---|---|
    | Metadata > Types > Read | `/metadata/types/read/` | `CertificateMetadataTypes:Read` |
    | Certificates > Enrollment > Csr | `/certificates/enrollment/csr/` | `CertificateEnrollment:EnrollCSR`  |

    > Documentation for [Version Two Permission Model](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SecurityRolePermissions.htm#VersionTwoPermissionModel) and [Version One Permission Model](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SecurityRolePermissions.htm#VersionOnePermissionModel)

![Permission Metadata Read](./docsource/images/security_permission_metadata_read.png)

![Permission Certificate CSR Enrollment](./docsource/images/security_permission_enrollment_csr.png)

![Certificate Authority Allowed Requester](./docsource/images/ca_allowed_requester.png)

![Certificate Template Allowed Requester](./docsource/images/cert_template_allowed_requester.png)

## Installing Command Issuer

Command Issuer is installed using a Helm chart. The chart is available in the [Command cert-manager Helm repository](https://keyfactor.github.io/command-cert-manager-issuer/).

1. Verify that at least one Kubernetes node is running:

    ```shell
    kubectl get nodes
    ```

2. Add the Helm repository:

    ```shell
    helm repo add command-issuer https://keyfactor.github.io/command-cert-manager-issuer
    helm repo update
    ```

3. Then, install the chart:

    ```shell
    helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer \
        --namespace command-issuer-system \
        --create-namespace 
    ```

> The Helm chart installs the Command Issuer CRDs by default. The CRDs can be installed manually with the `make install` target.

# Authentication

Command Issuer supports authentication to Command using one of the following methods:

- Basic Authentication (username and password)
- OAuth 2.0 "client credentials" token flow (sometimes called two-legged OAuth 2.0)

These credentials must be configured using a Kubernetes Secret. By default, the secret is expected to exist in the same namespace as the issuer controller (`command-issuer-system` by default). 

> Command Issuer can read secrets in the Issuer namespace if `--set "secretConfig.useClusterRoleForSecretAccess=true"` flag is set when installing the Helm chart.

Command Issuer also supports ambient authentication, where a token is fetched from an Authorization Server using a cloud provider's auth infrastructure and passed to Command directly. The following methods are supported:

- Managed Identity Using Azure Entra ID Workload Identity (if running in [AKS](https://azure.microsoft.com/en-us/products/kubernetes-service))

## Basic Auth

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

## OAuth

Create an Opaque secret containing the client ID and client secret to authenticate with Command:

```shell
token_url="<token url>"
client_id="<client id>"
client_secret="<client secret>"
audience="<audience>"
scopes="<scopes>" # comma separated list of scopes

kubectl -n command-issuer-system create secret generic command-secret \
    "--from-literal=tokenUrl=$token_url" \
    "--from-literal=clientId=$client_id" \
    "--from-literal=clientSecret=$client_secret" \
    "--from-literal=audience=$audience" \
    "--from-literal=scopes=$scopes"
```

> Audience and Scopes are optional

## Managed Identity Using Azure Entra ID Workload Identity (AKS)

Azure Entra ID workload identity in Azure Kubernetes Service (AKS) allows Command Issuer to exchange a Kubernetes ServiceAccount Token for an Azure Entra ID access token, which is then used to authenticate to Command.

At this time, Azure Kuberentes Services workload identity federation is best supported by [User Assigned Managed Identities](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-manage-user-assigned-managed-identities?pivots=identity-mi-methods-azp). Other identity solutions such as Azure AD Service Principals are not supported.

Here is a guide on how to use Azure User Assigned Managed Identities to authenticate your AKS workload with your Keyfactor Command instance.

1. Reconfigure the AKS cluster to enable workload identity federation.

    ```shell
    export CLUSTER_NAME=<cluster-name>
    export RESOURCE_GROUP=<resource-group>
    az aks update \
        --name ${CLUSTER_NAME} \
        --resource-group ${RESOURCE_GROUP} \
        --enable-oidc-issuer \
        --enable-workload-identity
    ```

    > The [Azure Workload Identity extension can be installed on non-AKS or self-managed clusters](https://azure.github.io/azure-workload-identity/docs/installation.html) if you're not using AKS.
    >
    > Refer to the [AKS documentation](https://learn.microsoft.com/en-us/azure/aks/workload-identity-deploy-cluster) for more information on the `--enable-workload-identity` feature.

2. Create a User Assigned Managed Identity in Azure.

    ```shell
    export IDENTITY_NAME=command-issuer
    az identity create --name "${IDENTITY_NAME}" --resource-group "${RESOURCE_GROUP}"
    ```
    > Read more about [the `az identity` command](https://learn.microsoft.com/en-us/cli/azure/identity?view=azure-cli-latest).

3. Reconfigure or deploy Command Issuer with extra labels for the Azure Workload Identity webhook, which will result in the Command Issuer controller Pod having an extra volume containing a Kubernetes ServiceAccount token which it will exchange for a token from Azure.

    ```shell
    export UAMI_CLIENT_ID=$(az identity show --name $IDENTITY_NAME --resource-group $RESOURCE_GROUP --query clientId --output tsv)

    echo "Identity Client ID: ${UAMI_CLIENT_ID}"

    helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer \
        --namespace command-issuer-system \
        --create-namespace \
        --set "fullnameOverride=command-cert-manager-issuer" \
        --set-string "podLabels.azure\.workload\.identity/use=true" \
        --set-string "serviceAccount.labels.azure\.workload\.identity/use=true" \
        --set-string "serviceAccount.annotations.azure\.workload\.identity/client-id=${UAMI_CLIENT_ID}"
    ```

    If successful, the Command Issuer Pod will have new environment variables and the Azure WI ServiceAccount token as a projected volume:

    ```shell
    kubectl -n command-issuer-system describe pod
    ```

    ```shell
    Containers:
      command-cert-manager-issuer:
        ...
        Environment:
          AZURE_CLIENT_ID:             <UAMI_CLIENT_ID>
          AZURE_TENANT_ID:             <GUID>
          AZURE_FEDERATED_TOKEN_FILE:  /var/run/secrets/azure/tokens/azure-identity-token
          AZURE_AUTHORITY_HOST:        https://login.microsoftonline.com/
        Mounts:
          /var/run/secrets/azure/tokens from azure-identity-token (ro)
          /var/run/secrets/kubernetes.io/serviceaccount from kube-api-access-6rmzz (ro)
    ...
    Volumes:
      ...
      azure-identity-token:
        Type:                    Projected (a volume that contains injected data from multiple sources)
        TokenExpirationSeconds:  3600
    ```

    > Refer to [Azure Workload Identity docs](https://azure.github.io/azure-workload-identity/docs/installation/mutating-admission-webhook.html) more information on the role of the Mutating Admission Webhook.

4. Associate a Federated Identity Credential (FIC) with the User Assigned Managed Identity. The FIC allows Command Issuer to act on behalf of the Managed Identity by telling Azure to expect:
    - The `iss` claim of the ServiceAccount token to match the cluster's OIDC Issuer. Azure will also use the Issuer URL to download the JWT signing certificate.
    - The `sub` claim of the ServiceAccount token to match the ServiceAccount's name and namespace.

    ```shell
    export SERVICE_ACCOUNT_NAME=command-cert-manager-issuer # This is the default Kubernetes ServiceAccount used by the Command Issuer controller.
    export SERVICE_ACCOUNT_NAMESPACE=command-issuer-system # This is the default namespace for Command Issuer used in this doc.

    export SERVICE_ACCOUNT_ISSUER=$(az aks show --resource-group $RESOURCE_GROUP --name $CLUSTER_NAME --query "oidcIssuerProfile.issuerUrl" -o tsv)
    az identity federated-credential create \
        --name "${IDENTITY_NAME}-federated-credentials" \
        --identity-name "${IDENTITY_NAME}" \
        --resource-group "${RESOURCE_GROUP}" \
        --issuer "${SERVICE_ACCOUNT_ISSUER}" \
        --subject "system:serviceaccount:${SERVICE_ACCOUNT_NAMESPACE}:${SERVICE_ACCOUNT_NAME}" \
        --audiences "api://AzureADTokenExchange"
    ```

    > Read more about [Workload Identity federation](https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation) in the Entra ID documentation.
    >
    > Read more about [the `az identity federated-credential` command](https://learn.microsoft.com/en-us/cli/azure/identity/federated-credential?view=azure-cli-latest).

5. Get the Managed Identity's Principal ID and Entra Identity Provider Information

  ```shell
  export UAMI_PRINCIPAL_ID=$(az identity show --name $IDENTITY_NAME --resource-group $RESOURCE_GROUP --query principalId --output tsv)
  export CURRENT_TENANT=$(az account show --query tenantId --output tsv)
  echo "UAMI Principal ID: ${UAMI_PRINCIPAL_ID}"

  echo "View then OIDC configuration for the Entra OIDC token issuer: https://login.microsoftonline.com/$CURRENT_TENANT/v2.0/.well-known/openid-configuration"
  
  echo "Authority: https://login.microsoftonline.com/$CURRENT_TENANT/v2.0"
  ```

  > **IMPORTANT NOTE**: The Microsoft Entra Identity Provider is associated with your Azure tenant ID. Multi-tenant Azure workloads will require a Command Identity Provider for each tenant. 

6. Add the Microsoft Entra ID as an [Identity Provider in Command](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/IdentityProviders.htm?Highlight=identity%20provider) using the identity provider information from the previous step, and [add the Managed Identity's Principal ID as an `OAuth Subject` claim to the Security Role](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SecurityOverview.htm?Highlight=Security%20Roles) created/identified earlier.

## Google Kubernetes Engine (GKE) Workload Identity

Google Kuberentes Engine (GKE) supports the ability to authenticate your GKE workloads using workload identity. 

By default, GKE clusters are assigned the [default service account](https://cloud.google.com/compute/docs/access/service-accounts#token) for your Google project. This service account is used to generate an ID token for your workload. However, you may opt to use [Workload Identity Federation](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#metadata-server) to your GKE cluster.

1. Get the OAuth Client and Identity Provider for your GKE Cluster

  Regardless if you are using the default service account or a custom service account, the following script will help you derive your GKE cluster's OAuth Client:

  ```shell
  export CLUSTER_NAME=<cluster-name>
  export GCLOUD_REGION=<region>
  export GCLOUD_PROJECT_ID=$(gcloud config get-value project) # populate with the current PROJECT_ID context
  export GCLOUD_PROJECT_NUMBER=$(gcloud projects describe $GCLOUD_PROJECT_ID --format="value(projectNumber)")
    
  export GCLOUD_SERVICE_ACCOUNT=$(gcloud container clusters describe $CLUSTER_NAME \
  --zone $GCLOUD_REGION \
  --format="value(nodeConfig.serviceAccount)")

  if [[ "$GCLOUD_SERVICE_ACCOUNT" == "default" ]]; then
    # Override service account with default compute service account
    GCLOUD_SERVICE_ACCOUNT="$GCLOUD_PROJECT_NUMBER-compute@developer.gserviceaccount.com"
  fi
  
  echo "Service account: $GCLOUD_SERVICE_ACCOUNT"
  
  # Get OAuth2 Client ID of service account
  export GCLOUD_SERVICE_ACCOUNT_CLIENT_ID=$(gcloud iam service-accounts describe $GCLOUD_SERVICE_ACCOUNT \
  --format="value(oauth2ClientId)")
  
  echo "Service account OAuth2 client ID: $GCLOUD_SERVICE_ACCOUNT_CLIENT_ID"
  
  echo "View the OIDC configuration for Google's OIDC token issuer: https://accounts.google.com/.well-known/openid-configuration"
  
  echo "Authority: https://accounts.google.com"
  ```

2. Add Google as an [Identity Provider in Command](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/IdentityProviders.htm?Highlight=identity%20provider) using the identity provider information from the previous step, and [add the Service Account's OAuth Client ID as an `OAuth Subject` claim to the Security Role](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/SecurityOverview.htm?Highlight=Security%20Roles) created/identified earlier.

# CA Bundle

If the Command API is configured to use a self-signed certificate or with a certificate whose issuer isn't widely trusted, the CA certificate must be provided as a Kubernetes secret.

```shell
kubectl -n command-issuer-system create secret generic command-ca-secret --from-file=ca.crt
```

# Creating Issuer and ClusterIssuer resources

The `command-issuer.keyfactor.com/v1alpha1` API version supports Issuer and ClusterIssuer resources. The Issuer resource is namespaced, while the ClusterIssuer resource is cluster-scoped.

For example, ClusterIssuer resources can be used to issue certificates for resources in multiple namespaces, whereas Issuer resources can only be used to issue certificates for resources in the same namespace.

1. **Prepare the `spec`**

    ```shell
    export HOSTNAME="<hostname>"
    export COMMAND_CA_HOSTNAME="<certificateAuthorityName>" # Only required for non-HTTPS CA types
    export COMMAND_CA_LOGICAL_NAME="<certificateAuthorityName>"
    export CERTIFICATE_TEMPLATE_SHORT_NAME="<certificateTemplateShortName>"
    ```

    The `spec` field of both the Issuer and ClusterIssuer resources use the following fields:
    | Field Name               | Description                                                                                                                                   |
    |--------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------|
    | hostname                 | The hostname of the Command API Server.                                                                                                           |
    | apiPath                 | (optional) The base path of the Command REST API. Defaults to `KeyfactorAPI`.                                                                                                           |
    | commandSecretName          | The name of the Kubernetes secret containing basic auth credentials or OAuth 2.0 credentials                                          |
    | caSecretName       | (optional) The name of the Kubernetes secret containing the CA certificate. Required if the Command API uses a self-signed certificate or it was signed by a CA that is not widely trusted.      |
    | certificateAuthorityLogicalName | The logical name of the Certificate Authority to use in Command. For example, `Sub-CA`                                                              |
    | certificateAuthorityHostname   | (optional) The hostname of the Certificate Authority specified by `certificateAuthorityLogicalName`. This field is usually only required if the CA in Command is a DCOM (MSCA-like) CA.                                                                     |
    | certificateTemplate     | The Short Name of the Certificate Template to use when this Issuer/ClusterIssuer enrolls CSRs.                                                                        |
    | scopes     | (Optional) If using ambient credentials, these scopes will be put on the access token generated by the ambient credentials' token provider, if applicable.   |
     | audience     | (Optional) If using ambient credentials, this audience will be put on the access token generated by the ambient credentials' token provider, if applicable. Google's ambient credential token provider generates an OIDC ID Token. If this value is not provided, it will default to `command`.  |

    > If a different combination of hostname/certificate authority/certificate template is required, a new Issuer or ClusterIssuer resource must be created. Each resource instantiation represents a single configuration.

2. **Create an Issuer or ClusterIssuer**

    - **Issuer**

        Create an Issuer resource using the environment variables prepared in step 1.

        ```yaml
        cat <<EOF > ./issuer.yaml
        apiVersion: command-issuer.keyfactor.com/v1alpha1
        kind: Issuer
        metadata:
          name: issuer-sample
          namespace: default
        spec:
          hostname: "$HOSTNAME"
          apiPath: "/KeyfactorAPI" # Preceding & trailing slashes are handled automatically
          commandSecretName: "command-secret" # references the secret created above
          caSecretName: "command-ca-secret" # references the secret created above

          # certificateAuthorityHostname: "$COMMAND_CA_HOSTNAME" # Uncomment if required
          certificateAuthorityLogicalName: "$COMMAND_CA_LOGICAL_NAME"
          certificateTemplate: "$CERTIFICATE_TEMPLATE_SHORT_NAME"
          # scopes: "openid email https://example.com/.default" # Uncomment if desired
          # audience: "https://your-command-url.com" # Uncomment if desired
        EOF

        kubectl -n default apply -f issuer.yaml
        ```

    - **ClusterIssuer**
        
        Create a ClusterIssuer resource using the environment variables prepared in step 1.

        ```yaml
        cat <<EOF > ./clusterissuer.yaml
        apiVersion: command-issuer.keyfactor.com/v1alpha1
        kind: ClusterIssuer
        metadata:
          name: clusterissuer-sample
        spec:
          hostname: "$HOSTNAME"
          apiPath: "/KeyfactorAPI" # Preceding & trailing slashes are handled automatically 
          commandSecretName: "command-secret" # references the secret created above
          caSecretName: "command-ca-secret" # references the secret created above

          # certificateAuthorityHostname: "$COMMAND_CA_HOSTNAME" # Uncomment if required
          certificateAuthorityLogicalName: "$COMMAND_CA_LOGICAL_NAME"
          certificateTemplate: "$CERTIFICATE_TEMPLATE_SHORT_NAME"
          # scopes: "openid email https://example.com/.default" # Uncomment if desired
          # audience: "https://your-command-url.com" # Uncomment if desired
        EOF

        kubectl apply -f clusterissuer.yaml
        ```

# Creating a Certificate

Once an Issuer or ClusterIssuer resource is created, they can be used to issue certificates using cert-manager. The two most important concepts are `Certificate` and `CertificateRequest` resources. 

1. `Certificate` resources represent a single X.509 certificate and its associated attributes. cert-manager maintains the corresponding certificate, including renewal when appropriate. 
2. When `Certificate` resources are created, cert-manager creates a corresponding `CertificateRequest` that targets a specific Issuer or ClusterIssuer to actually issue the certificate.

> To learn more about cert-manager, see the [cert-manager documentation](https://cert-manager.io/docs/).

The following is an example of a Certificate resource. This resource will create a corresponding CertificateRequest resource, and will use the `issuer-sample` Issuer resource to issue the certificate. Once issued, the certificate will be stored in a Kubernetes secret named `command-certificate`.

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: command-certificate
spec:
  issuerRef:
    name: issuer-sample
    group: command-issuer.keyfactor.com
    kind: Issuer
  commonName: example.com
  secretName: command-certificate
```

> Certificate resources support many more fields than the above example. See the [Certificate resource documentation](https://cert-manager.io/docs/usage/certificate/) for more information.

Similarly, a CertificateRequest resource can be created directly. The following is an example of a CertificateRequest resource.
```yaml
apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata:
  name: command-certificate
spec:
  issuerRef:
    name: issuer-sample
    group: command-issuer.keyfactor.com
    kind: Issuer
  request: <csr>
```

> All fields in Command Issuer and ClusterIssuer `spec` can be overridden by applying Kubernetes Annotations to Certificates _and_ CertificateRequests. See [runtime customization for more](docs/annotations.md) 

## Approving Certificate Requests

Unless the cert-manager internal approver automatically approves the request, newly created CertificateRequest resources
will be in a `Pending` state until they are approved. CertificateRequest resources can be approved manually by using
[cmctl](https://cert-manager.io/docs/reference/cmctl/#approve-and-deny-certificaterequests). The following is an example
of approving a CertificateRequest resource named `command-certificate`.
```shell
cmctl approve command-certificate
```

Once a certificate request has been approved, the certificate will be issued and stored in the secret specified in the
CertificateRequest resource. The following is an example of retrieving the certificate from the secret.
```shell
kubectl get secret command-certificate -o jsonpath='{.data.tls\.crt}' | base64 -d
```

> To learn more about certificate approval and RBAC configuration, see the [cert-manager documentation](https://cert-manager.io/docs/concepts/certificaterequest/#approval).

## Overriding the Issuer/ClusterIssuer `spec` using Kubernetes Annotations on CertificateRequest Resources

Command Issuer allows you to override the `certificateAuthorityHostname`, `certificateAuthorityLogicalName`, and `certificateTemplate` by setting Kubernetes Annotations on CertificateRequest resources. This may be useful if certain enrollment scenarios require a different Certificate Authority or Certificate Template, but you don't want to create a new Issuer/ClusterIssuer.

- `command-issuer.keyfactor.com/certificateAuthorityHostname` overrides `certificateAuthorityHostname`
- `command-issuer.keyfactor.com/certificateAuthorityLogicalName` overrides `certificateAuthorityLogicalName`
- `command-issuer.keyfactor.com/certificateTemplate` overrides `certificateTemplate`

> cert-manager copies Annotations set on Certificate resources to the corresponding CertificateRequest.

> **How to Apply Annotations**
> <details><summary>Notes</summary>
>
> To apply these annotations, include them in the metadata section of your Certificate/CertificateRequest resource:
>
> ```yaml
> apiVersion: cert-manager.io/v1
> kind: Certificate
> metadata:
>   annotations:
>     command-issuer.keyfactor.com/certificateTemplate: "Ephemeral2day"
>     command-issuer.keyfactor.com/certificateAuthorityLogicalName: "InternalIssuingCA1"
>     metadata.command-issuer.keyfactor.com/ResponsibleTeam: "theResponsibleTeam@example.com"
>     # ... other annotations
> spec:
> # ... the rest of the spec
> ```
> </details>

# Certificate Metadata

Keyfactor Command allows users to [attach custom metadata to certificates](https://software.keyfactor.com/Core/Current/Content/ReferenceGuide/Certificate%20Metadata.htm) that can be used to tag certificates with additional information. Command Issuer can attach Certificate Metadata upon enrollment.

- **Pre-defined Certificate Metadata**

    If **all of the following metadata fields are defined** in Command, Command Issuer will populate the fields upon certificate enrollment. All of the metadata fields are String types. Please refer to the [Command docs](https://software.keyfactor.com/Core/Current/Content/ReferenceGuide/Certificate%20Metadata.htm) to define these metadata fields in Command if you would like Command Issuer to populate these fields on certificates upon enrollment.

    | Field Name                          | Description                                                                                                     |
    |-------------------------------------|-----------------------------------------------------------------------------------------------------------------|
    | Issuer-Namespace                    | The namespace that the Issuer resource was created in. Is always empty for ClusterIssuers.                      |
    | Controller-Reconcile-Id             | The GUID of the reconciliation run that corresponded to the issuance of this certificate.                                |
    | Certificate-Signing-Request-Namespace | The namespace that the CertificateRequest resource was created in.                                      |
    | Controller-Namespace                | The namespace that the controller container is running in.                                                     |
    | Controller-Kind                     | The issuer type - Issuer or ClusterIssuer.                                         |
    | Controller-Resource-Group-Name      | The group name of the Command Issuer CRD. Is always `command-issuer.keyfactor.com`.                        |
    | Issuer-Name                         | The name of the K8s Issuer/ClusterIssuer resource.                                                                           |

    > You don't need to re-create the Issuer/ClusterIssuer when metadata fields are added/removed in Command. Command Issuer automatically detects the presence of these fields and tracks the state in the `SupportsMetadata` resource condition.

- **Custom Certificate Metadata**

    You can **_also_** configure Command Issuer to attach Certificate Metadata by annotating Certificate/CertificateRequest resources. Command Issuer does not check for the presence of custom metadata fields configured in Annotations, and you should take special care that fields defined in annotations exist in Command prior to use. Certificate issuance will fail if any of the metadata fields specified aren't configured in Command. The syntax for specifying metadata is as follows:

    ```yaml
    metadata.command-issuer.keyfactor.com/<metadata-field-name>: <metadata-value>
    ```



## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor integrations](https://github.com/topics/keyfactor-integration).