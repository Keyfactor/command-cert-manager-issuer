# Google Kubernetes Engine (GKE) Workload Identity

This documentation is for instructions on using ambient credentials within Google Kubernetes Engine (GKE). Full documentation on Command Cert Manager Issuer can be found [here](../../README.md).

## Prerequisites

- [cert-manager](https://cert-manager.io/docs/installation/helm/) installed to your GKE cluster.
- [command-cert-manager-issuer](../../README.md#installing-command-issuer) installed to your GKE cluster.
- [Issuer or ClusterIssuer](../../README.md#creating-issuer-and-clusterissuer-resources) resources deployed to your GKE cluster.
  - to use ambient credentials, do not supply a `commandSecretName` to your issuer's specification. `scopes` and `audience` fields are optional.
- [Gcloud CLI](https://cloud.google.com/sdk/docs/install) installed and logged in

## Background

Google Kuberentes Engine (GKE) supports the ability to authenticate your GKE workloads using workload identity. 

By default, GKE clusters are assigned the [default service account](https://cloud.google.com/compute/docs/access/service-accounts#token) for your Google project. This service account is used to generate an ID token for your workload. However, you may opt to use [Workload Identity Federation](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity#metadata-server) to your GKE cluster.

## How to use Workload Identity

1. Get the OAuth Client and Identity Provider for your GKE Cluster

  Regardless if you are using the default service account or a custom service account, the following script will help you derive your GKE cluster's OAuth Client:

  ```shell
  export CLUSTER_NAME="" # name of your GKE cluster
  export GCLOUD_REGION="" # region your cluster is hosted in
  export GCLOUD_PROJECT_ID=$(gcloud config get-value project) # populate with the current PROJECT_ID context
  export GCLOUD_PROJECT_NUMBER=$(gcloud projects describe $GCLOUD_PROJECT_ID --format="value(projectNumber)")
    
  export GCLOUD_SERVICE_ACCOUNT=$(gcloud container clusters describe $CLUSTER_NAME \
  --zone $GCLOUD_REGION \
  --format="value(nodeConfig.serviceAccount)")

  echo "Cluster name: $CLUSTER_NAME"
  echo "Region: $GCLOUD_REGION"
  echo "Project ID: $GCLOUD_PROJECT_ID"
  echo "Project Number: $GCLOUD_PROJECT_NUMBER"

  if [[ "$GCLOUD_SERVICE_ACCOUNT" == "default" ]]; then
    echo "Overriding service account..."
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