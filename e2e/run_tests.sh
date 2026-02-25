#!/bin/bash

## =======================   LICENSE     ===================================
# Copyright © 2026 Keyfactor
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## ==========================================================================

## ======================= Description ===================================

# This script automates the deployment of the command-cert-manager-issuer
# and runs end-to-end tests to validate its functionality.
# This script is intended for use in a Minikube environment.
# This script can be run multiple times to test various scenarios.

## =======================================================================

## ======================= How to run ===================================
# Enable the script to run:
# > chmod +x run_tests.sh
# Load the environment variables:
# > source .env
# Run the tests:
# > ./run_tests.sh
## ===========================================================================


# Image configuration - can be overridden via environment variables
# Set IMAGE_TAG=local to build locally, or use a published version (default: 2.5.0)
IMAGE_REPO="${IMAGE_REPO:-keyfactor}"
IMAGE_NAME="${IMAGE_NAME:-command-cert-manager-issuer}"
IMAGE_TAG="${IMAGE_TAG:-2.5.0}"
FULL_IMAGE_NAME="${IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}"

# Helm chart configuration - can be overridden via environment variables
# Set HELM_CHART_VERSION=local to use the local chart, or use a published version (default: 2.5.0)
HELM_CHART_NAME="command-cert-manager-issuer"
HELM_CHART_VERSION="${HELM_CHART_VERSION:-2.5.0}"

IS_LOCAL_DEPLOYMENT=$([ "$IMAGE_TAG" = "local" ] && echo "true" || echo "false")
IS_LOCAL_HELM=$([ "$HELM_CHART_VERSION" = "local" ] && echo "true" || echo "false")

ISSUER_TYPE="Issuer"
CLUSTER_ISSUER_TYPE="ClusterIssuer"

#ISSUER_OR_CLUSTER_ISSUER="ClusterIssuer"
ISSUER_OR_CLUSTER_ISSUER="Issuer"
ISSUER_CR_NAME="issuer"
ISSUER_CRD_FQTN="issuers.command-issuer.keyfactor.com"
CLUSTER_ISSUER_CRD_FQTN="clusterissuers.command-issuer.keyfactor.com"

ENROLLMENT_PATTERN_ID=${E2E_ENROLLMENT_PATTERN_ID:-1}
ENROLLMENT_PATTERN_NAME="${E2E_ENROLLMENT_PATTERN_NAME:-Default Pattern}"

OWNER_ROLE_ID=${E2E_OWNER_ROLE_ID:-2}
OWNER_ROLE_NAME="${E2E_OWNER_ROLE_NAME:-InstanceOwner}"

CHART_PATH="./deploy/charts/command-cert-manager-issuer"

CERT_MANAGER_VERSION="v1.17.0"

MANAGER_NAMESPACE="command-issuer-system"
CERT_MANAGER_NAMESPACE="cert-manager"
ISSUER_NAMESPACE="issuer-playground"

SIGNER_SECRET_NAME="auth-secret"

CERTIFICATE_CRD_FQTN="certificates.cert-manager.io"
CERTIFICATEREQUEST_CRD_FQTN="certificaterequests.cert-manager.io"

CA_CERTS_PATH="e2e/certs"
SIGNER_CA_SECRET_NAME="ca-trust-secret"
SIGNER_CA_CONFIGMAP_NAME="ca-trust-configmap"

CR_C_NAME="command-cert"
CR_CR_NAME="command-cert-1"
CR_C_SECRET_NAME="$CR_C_NAME-tls"

set -e # Exit on any error

# checks if environment variable is available in system. if it is not present but the variable is required
# an error is thrown
validate_env_present() {
    local env_var=$1
    local required=$2
    if [ -z "${!env_var}" ]; then
        if [ "$required" = "false" ]; then
            echo "ℹ️    Optional environment variable $env_var is not set. Continuing..."
            return 0
        fi
        echo "⚠️    Required environment variable $env_var. Please check your .env file or set it in your shell."
        echo "     Run: source .env or export $env_var=<value>"
        exit 1
    fi
}

# checks whether the following environment variables are provided. some environment variables are optional.
check_env() {
    validate_env_present HOSTNAME true
    validate_env_present API_PATH true
    validate_env_present CERTIFICATE_TEMPLATE true
    validate_env_present CERTIFICATE_AUTHORITY_LOGICAL_NAME true
    validate_env_present OAUTH_TOKEN_URL true
    validate_env_present OAUTH_CLIENT_ID true
    validate_env_present OAUTH_CLIENT_SECRET true
    validate_env_present OAUTH_AUDIENCE false
    validate_env_present OAUTH_SCOPES false

    validate_env_present CERTIFICATE_AUTHORITY_HOSTNAME false
    validate_env_present DISABLE_CA_CHECK false
}

# checks whether the provided kubernetes namespace exists
ns_exists () {
    local ns=$1
    if [ "$(kubectl get namespace -o json | jq --arg namespace "$ns" -e '.items[] | select(.metadata.name == $namespace) | .metadata.name')" ]; then
        return 0
    fi
    return 1
}

# checks whether the provided helm chart has been deployed to the cluster (namespaced)
helm_exists () {
    local namespace=$1
    local chart_name=$2
    if helm list -n "$namespace" | grep -q "$chart_name"; then
        return 0
    fi
    return 1
}

# checks whether the provided custom resource can be found in the cluster (namespaced)
cr_exists () {
    local fqtn=$1
    local ns=$2
    local name=$3
    if [ "$(kubectl -n "$ns" get "$fqtn" -o json | jq --arg name "$name" -e '.items[] | select(.metadata.name == $name) | .metadata.name')" ]; then
        echo "$fqtn exists called $name in $ns"
        return 0
    fi
    return 1
}

# checks whether the provided secret name exists in the cluster (namespaced)
secret_exists () {
    local ns=$1
    local name=$2
    if [ "$(kubectl -n "$ns" get secret -o json | jq --arg name "$name" -e '.items[] | select(.metadata.name == $name) | .metadata.name')" ]; then
        echo "secret exists called $name in $ns"
        return 0
    fi
    return 1
}

# installs cert-manager onto the Kubernetes cluster
install_cert_manager() {
    echo "📦 Installing cert-manager..."

    # Add jetstack repository if not already added
    if ! helm repo list | grep -q jetstack; then
        echo "Adding jetstack Helm repository..."
        helm repo add jetstack https://charts.jetstack.io
    fi

    helm repo update

    echo "Installing cert-manager version ${CERT_MANAGER_VERSION}..."

    helm install cert-manager jetstack/cert-manager \
        --namespace ${CERT_MANAGER_NAMESPACE} \
        --create-namespace \
        --version ${CERT_MANAGER_VERSION} \
        --set crds.enabled=true \
        --wait

    echo "✅ cert-manager installed successfully"
}

# installs the issuer to the Kubernetes cluster
install_cert_manager_issuer() {
    echo "📦 Installing instance of $IMAGE_NAME with tag $IMAGE_TAG..."
    
    
    if [[ "$IS_LOCAL_HELM" == "true" ]]; then
        CHART_PATH=$CHART_PATH

        # Checking if chart path exists
        if [ ! -d "$CHART_PATH" ]; then
            echo "⚠️ Chart path not found at ${CHART_PATH}. Are you in the correct directory?"
            exit 1
        fi

        VERSION_PARAM=""
    else
        # Add command-issuer repository if not already added
        if ! helm repo list | grep -q command-issuer; then
            echo "Adding command-issuer Helm repository..."
            helm repo add command-issuer https://keyfactor.github.io/command-cert-manager-issuer
        fi

        CHART_PATH="command-issuer/command-cert-manager-issuer"
        echo "Using Helm chart from repository for version ${HELM_CHART_VERSION}: $CHART_PATH..."
        
        # Only include --devel if HELM_CHART_VERSION is a pre-release (contains -alpha, -beta, -rc, etc.)
        if [[ "${HELM_CHART_VERSION}" =~ -alpha|-beta|-rc ]]; then
            VERSION_PARAM="--version ${HELM_CHART_VERSION} --devel"
        else
            VERSION_PARAM="--version ${HELM_CHART_VERSION}"
        fi
    fi

    # Only set the image repository parameter if we are deploying locally
    if [[ "$IS_LOCAL_DEPLOYMENT" == "true" ]]; then
        IMAGE_REPO_PARAM="--set image.repository=${IMAGE_REPO}/${IMAGE_NAME}"
    else
        IMAGE_REPO_PARAM=""
    fi

    

    # Only set the pull policy to Never if we are deploying locally
    if [[ "$IS_LOCAL_DEPLOYMENT" == "true" ]]; then
        PULL_POLICY_PARAM="--set image.pullPolicy=Never"
    else
        PULL_POLICY_PARAM=""
    fi
    
    # Helm chart could be out of date for release candidates, so we will install from
    # the chart defined in the repository.
    helm install $IMAGE_NAME ${CHART_PATH} \
        --namespace ${MANAGER_NAMESPACE} \
        $VERSION_PARAM \
        $IMAGE_REPO_PARAM \
        --set "fullnameOverride=${IMAGE_NAME}" \
        --set image.tag=${IMAGE_TAG} \
        $PULL_POLICY_PARAM \
        --wait \
        --timeout 30s
        
    echo "✅ $IMAGE_NAME installed successfully"
}

# performs a redeployment of the cert-manager. helpful for recycling TLS certificates that have expired.
deploy_cert_manager() {
    # Restart all cert-manager components
    kubectl rollout restart deployment/cert-manager -n ${CERT_MANAGER_NAMESPACE}
    kubectl rollout restart deployment/cert-manager-webhook -n ${CERT_MANAGER_NAMESPACE}
    kubectl rollout restart deployment/cert-manager-cainjector -n ${CERT_MANAGER_NAMESPACE}

    # Wait for them to be ready
    kubectl rollout status deployment/cert-manager -n ${CERT_MANAGER_NAMESPACE}
    kubectl rollout status deployment/cert-manager-webhook -n ${CERT_MANAGER_NAMESPACE}
    kubectl rollout status deployment/cert-manager-cainjector -n ${CERT_MANAGER_NAMESPACE}
}

# deploys the issuer to the Kubernetes cluster
deploy_cert_manager_issuer() {
    # Find the deployment name (assuming it follows a pattern)
    DEPLOYMENT_NAME=$(kubectl get deployments -n ${MANAGER_NAMESPACE} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "$IMAGE_NAME")

    # Between runs, we want to make sure that the running issuer has the latest version of the code we want.
    # Doing this patch and redeployment forces the container to restart with the latest desired version
    if kubectl get deployment ${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE} >/dev/null 2>&1; then
        # Patch the deployment
        kubectl patch deployment ${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE} -p "{
            \"spec\": {
                \"template\": {
                    \"spec\": {
                        \"containers\": [{
                            \"name\": \"${IMAGE_NAME}\",
                            \"image\": \"${FULL_IMAGE_NAME}\",
                            \"imagePullPolicy\": \"Never\"
                        }]
                    }
                }
            }
        }"

        # Rollout deployment changes and apply the patch
        kubectl rollout restart deployment/${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE}
            kubectl rollout status deployment/${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE} --timeout=300s


        echo "✅ Deployment patched and rolled out successfully"
    else
        echo "⚠️  Deployment ${DEPLOYMENT_NAME} not found. The Helm chart might use a different naming convention."
        echo "Available deployments in ${MANAGER_NAMESPACE}:"
        kubectl get deployments -n ${MANAGER_NAMESPACE}
    fi

    echo ""
    echo "🎉 Deployment complete!"
    echo ""
}

# check the expiration of the cert-manager TLS certificate
check_cert_manager_webhook_cert() {
    local namespace=${1:-cert-manager}
    local secret_name=${2:-cert-manager-webhook-ca}
    
    echo "🔍 Checking cert-manager webhook certificate..."
    
    # Check if secret exists
    if ! kubectl get secret "$secret_name" -n "$namespace" >/dev/null 2>&1; then
        echo "❌ Secret $secret_name not found in namespace $namespace"
        return 1
    fi
    
    # Get certificate data
    local cert_data=$(kubectl get secret "$secret_name" -n "$namespace" -o jsonpath='{.data.tls\.crt}' 2>/dev/null)
    
    if [ -z "$cert_data" ]; then
        echo "❌ No certificate data found in secret"
        return 1
    fi
    
    # Decode and check certificate
    local cert_info=$(echo "$cert_data" | base64 -d | openssl x509 -noout -dates 2>/dev/null)
    
    if [ $? -ne 0 ]; then
        echo "❌ Failed to parse certificate"
        return 1
    fi
    
    echo "📋 Certificate validity:"
    echo "$cert_info"
    
    # Check if certificate is currently valid
    if echo "$cert_data" | base64 -d | openssl x509 -noout -checkend 0 >/dev/null 2>&1; then
        echo "✅ Certificate is currently valid"
        
        # Check if expires within 7 days
        if ! echo "$cert_data" | base64 -d | openssl x509 -noout -checkend 604800 >/dev/null 2>&1; then
            echo "⚠️  Certificate expires within 7 days"
            return 2  # Warning status
        fi
        
        return 0  # Valid
    else
        echo "❌ Certificate is expired or not yet valid"
        return 1  # Expired
    fi
}

# creates a new issuer custom resource
create_issuer() {
    echo "🔐 Creating issuer resource..."

    secretJson='{}'
    secretJson=$(echo "$secretJson" | jq --arg version "v1" '.apiVersion = $version')
    secretJson=$(echo "$secretJson" | jq --arg kind "Secret" '.kind = $kind')
    secretJson=$(echo "$secretJson" | jq --arg name "$SIGNER_SECRET_NAME" '.metadata.name = $name')

    # OAuth credentials
    secretJson=$(echo "$secretJson" | jq --arg type "Opaque" '.type = $type')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_TOKEN_URL" '.stringData.tokenUrl = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_CLIENT_ID" '.stringData.clientId = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_CLIENT_SECRET" '.stringData.clientSecret = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_AUDIENCE" '.stringData.audience = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_SCOPES" '.stringData.scopes = $val')

    echo "Creating secret called $SIGNER_SECRET_NAME in namespace $MANAGER_NAMESPACE"
    if ! echo "$secretJson" | yq -P | kubectl -n "$MANAGER_NAMESPACE" apply -f -; then
        echo "Failed to create $SIGNER_SECRET_NAME"
        return 1
    fi

    regenerate_ca_secret
    regenerate_ca_config_map

    caSecretNameSpec="caSecretName: $SIGNER_CA_SECRET_NAME"
    if [[ "$DISABLE_CA_CHECK" == "true" ]]; then
        echo "⚠️ Disabling CA check as per DISABLE_CA_CHECK environment variable"
        caSecretNameSpec=""
    fi

    kubectl -n "$ISSUER_NAMESPACE" apply -f - <<EOF
apiVersion: command-issuer.keyfactor.com/v1alpha1
kind: Issuer
metadata:
  name: "$ISSUER_CR_NAME"
spec:
  hostname: "$HOSTNAME"
  apiPath: "$API_PATH"
  commandSecretName: "$SIGNER_SECRET_NAME"
  $caSecretNameSpec
  certificateTemplate: "$CERTIFICATE_TEMPLATE"
  certificateAuthorityLogicalName: "$CERTIFICATE_AUTHORITY_LOGICAL_NAME"
  certificateAuthorityHostname: "$CERTIFICATE_AUTHORITY_HOSTNAME"
EOF


    echo "✅ Issuer resources created successfully"
}

# creates a new cluster issuer custom resource
create_cluster_issuer() {
    echo "🔐 Creating cluster issuer resource..."

    secretJson='{}'
    secretJson=$(echo "$secretJson" | jq --arg version "v1" '.apiVersion = $version')
    secretJson=$(echo "$secretJson" | jq --arg kind "Secret" '.kind = $kind')
    secretJson=$(echo "$secretJson" | jq --arg name "$SIGNER_SECRET_NAME" '.metadata.name = $name')

    # OAuth credentials
    secretJson=$(echo "$secretJson" | jq --arg type "Opaque" '.type = $type')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_TOKEN_URL" '.stringData.tokenUrl = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_CLIENT_ID" '.stringData.clientId = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_CLIENT_SECRET" '.stringData.clientSecret = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_AUDIENCE" '.stringData.audience = $val')
    secretJson=$(echo "$secretJson" | jq --arg val "$OAUTH_SCOPES" '.stringData.scopes = $val')

    echo "Creating secret called $SIGNER_SECRET_NAME in namespace $MANAGER_NAMESPACE"
    if ! echo "$secretJson" | yq -P | kubectl -n "$MANAGER_NAMESPACE" apply -f -; then
        echo "Failed to create $SIGNER_SECRET_NAME"
        return 1
    fi

    regenerate_ca_secret
    regenerate_ca_config_map

    caSecretNameSpec="caSecretName: $SIGNER_CA_SECRET_NAME"
    if [[ "$DISABLE_CA_CHECK" == "true" ]]; then
        echo "⚠️ Disabling CA check as per DISABLE_CA_CHECK environment variable"
        caSecretNameSpec=""
    fi

    kubectl -n "$ISSUER_NAMESPACE" apply -f - <<EOF
apiVersion: command-issuer.keyfactor.com/v1alpha1
kind: ClusterIssuer
metadata:
  name: "$ISSUER_CR_NAME"
spec:
  hostname: "$HOSTNAME"
  apiPath: "$API_PATH"
  commandSecretName: "$SIGNER_SECRET_NAME"
  $caSecretNameSpec
  certificateTemplate: "$CERTIFICATE_TEMPLATE"
  certificateAuthorityLogicalName: "$CERTIFICATE_AUTHORITY_LOGICAL_NAME"
  certificateAuthorityHostname: "$CERTIFICATE_AUTHORITY_HOSTNAME"
EOF


    echo "✅ Issuer resources created successfully"
}

# deletes Issuer and ClusterIssuer custom resources from the Kubernetes cluster
delete_issuers() {
    echo "🗑️ Deleting issuer resources..."

    if cr_exists "$ISSUER_CRD_FQTN" "$ISSUER_NAMESPACE" "$ISSUER_CR_NAME"; then
        echo "Deleting Issuer $ISSUER_CRD_FQTN called $ISSUER_CR_NAME in $ISSUER_NAMESPACE"
        kubectl -n "$ISSUER_NAMESPACE" delete "$ISSUER_CRD_FQTN" "$ISSUER_CR_NAME"
    fi
    if cr_exists "$CLUSTER_ISSUER_CRD_FQTN" "$ISSUER_NAMESPACE" "$ISSUER_CR_NAME"; then
        echo "Deleting ClusterIssuer $CLUSTER_ISSUER_CRD_FQTN called $ISSUER_CR_NAME in $ISSUER_NAMESPACE"
        kubectl -n "$ISSUER_NAMESPACE" delete "$CLUSTER_ISSUER_CRD_FQTN" "$ISSUER_CR_NAME"
    fi
    if secret_exists "$MANAGER_NAMESPACE" "$SIGNER_SECRET_NAME" ; then
        echo "Deleting authentication secret called $SIGNER_SECRET_NAME"
        kubectl -n "$MANAGER_NAMESPACE" delete secret "$SIGNER_SECRET_NAME"
    fi
    if secret_exists "$MANAGER_NAMESPACE" "$SIGNER_CA_SECRET_NAME" ; then
        echo "Deleting CA secret called $SIGNER_CA_SECRET_NAME"
        kubectl -n "$MANAGER_NAMESPACE" delete secret "$SIGNER_CA_SECRET_NAME"
    fi

    echo "✅ Issuer resources deleted successfully"
}

# creates a Certificate custom resource. this is picked up by cert-manager and converted to a CertificateRequest.
create_certificate() {
    local issuer_type=$1

    echo "Generating a certificate object for issuer type: $issuer_type"

    kubectl -n "$ISSUER_NAMESPACE" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: $CR_C_NAME
spec:
  secretName: ${CR_C_SECRET_NAME}  # Where the Secret will be created
  commonName: example.com
  usages:
    - signing
    - digital signature
    - server auth
    # 90 days
  duration: 2160h
  privateKey:
    algorithm: RSA
    size: 2048
  issuerRef:
    name: $ISSUER_CR_NAME
    group: command-issuer.keyfactor.com
    kind: $issuer_type
EOF
}

# deletes the Certificate custom resource
delete_certificate() {
    echo "🗑️ Deleting certificate..."

    if cr_exists $CERTIFICATE_CRD_FQTN "$ISSUER_NAMESPACE" "$CR_C_NAME"; then
        echo "Deleting Certificate called $CR_C_NAME in $ISSUER_NAMESPACE"
        kubectl -n "$ISSUER_NAMESPACE" delete certificate "$CR_C_NAME"
    else
        echo "⚠️ Certificate $CR_C_NAME not found in $ISSUER_NAMESPACE"
    fi
}

# deletes the Secret associated with the Certificate resource
delete_certificate_secret() {
    echo "🗑️ Deleting certificate secret $CR_C_SECRET_NAME..."

    if secret_exists "$ISSUER_NAMESPACE" "$CR_C_SECRET_NAME"; then
        kubectl -n "$ISSUER_NAMESPACE" delete secret "$CR_C_SECRET_NAME"
    else
        echo "⚠️ Certificate secret $CR_C_SECRET_NAME not found in $ISSUER_NAMESPACE"
    fi
}

create_certificate_request() {
    local issuer_type=$1

    local cn=$(openssl rand -hex 12)

    echo "Generating a certificate request for issuer type: $issuer_type. CN: $cn"

    openssl req -new \
                -newkey rsa:2048 \
                -nodes \
                -keyout random.key \
                -out random.csr \
                -subj "/CN=$cn" > /dev/null 2>&1

    kubectl -n "$ISSUER_NAMESPACE" apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: CertificateRequest
metadata:
    name: $CR_CR_NAME
    # annotations:
    #     metadata.command-issuer.keyfactor.com/TestField: "How did we get here"
spec:
    request: "$(base64 -i random.csr | tr -d '\n' | tr -d '\r')"
    isCA: false
    usages:
    - signing
    - digital signature
    - server auth
    # 90 days
    duration: 2160h
    issuerRef:
        name: $ISSUER_CR_NAME
        group: command-issuer.keyfactor.com
        kind: $issuer_type
EOF
        
        rm random.csr random.key
        echo "Certificate request created successfully."
}

# deletes the CertificateRequest custom resource
delete_certificate_request() {
    echo "🗑️ Deleting certificate request..."

    if cr_exists $CERTIFICATEREQUEST_CRD_FQTN "$ISSUER_NAMESPACE" "$CR_CR_NAME"; then
        echo "Deleting CertificateRequest called $CR_CR_NAME in $ISSUER_NAMESPACE"
        kubectl -n "$ISSUER_NAMESPACE" delete certificaterequest "$CR_CR_NAME"
    else
        echo "⚠️ CertificateRequest $CR_CR_NAME not found in $ISSUER_NAMESPACE"
    fi

    echo "✅ Certificate request deleted successfully"
}

regenerate_certificate() {
    local issuer_type=$1
    delete_certificate_secret # delete existing certificate secret so that a new CertificateRequest can be generated
    delete_certificate_request # delete stale CertificateRequest resource
    delete_certificate # delete stale Certificate resource
    create_certificate $issuer_type
}

regenerate_certificate_request() {
    local issuer_type=$1
    delete_certificate_request
    create_certificate_request $issuer_type 
}

# cert-manager will take care of generating a CertificateRequest resource from the Certificate resource.
# This does take a few seconds to complete
wait_for_certificate_request() {
    local timeout=30

    echo "🕰️ Waiting for certificate request to exist..."

    local end_time=$(($(date +%s) + timeout))

    while [ $(date +%s) -lt $end_time ]; do
        local cr_count=$(kubectl -n issuer-playground get certificaterequests -o json | \
            jq -r '.items[] | .metadata.name' | wc -l)

        cr_count=$(echo "$cr_count" | tr -d ' ')

        if [ "$cr_count" -gt 0 ]; then
            echo "✅ CertificateRequest created"
            return 0
        fi

        sleep 2
    done

    echo "❌ No CertificateRequest found for Certificate '$CR_C_NAME' within ${timeout}s"
    return 1
}

# approve the CertificateRequest so that the issuer can perform work on the resource
approve_certificate_request() {
    echo "🔍 Approving certificate request..."

    sleep 1

    if cr_exists $CERTIFICATEREQUEST_CRD_FQTN "$ISSUER_NAMESPACE" "$CR_CR_NAME"; then
        cmctl -n $ISSUER_NAMESPACE approve $CR_CR_NAME
        echo "Certificate request approved successfully."
    else
        echo "⚠️ CertificateRequest $CR_CR_NAME not found in $ISSUER_NAMESPACE"
    fi
}

# If the issuer issues the certificate, the CertificateRequest resource will have its Ready property set to True
check_certificate_request_status() {
    echo "🔎 Checking certificate request status..."

    if [[ ! $(kubectl wait --for=condition=Ready certificaterequest/$CR_CR_NAME -n $ISSUER_NAMESPACE --timeout=70s) ]]; then
        echo "⚠️  Certificate request did not become ready within the timeout period."
        echo "Check the Issuer / ClusterIssuer logs for errors. Check the configuration of your Issuer or CertificateRequest resources."
        echo "🚫 Test failed"
        exit 1
    fi

    echo "✅ Certificate request was issued successfully."
}

check_for_certificate_secret() {
    echo "🔎 Checking to see if certificate secret was created..."

    if secret_exists "$ISSUER_NAMESPACE" "$CR_C_SECRET_NAME"; then
        echo "✅ Certificate secret $CR_C_SECRET_NAME was found in $ISSUER_NAMESPACE"
        return 0
    fi

    echo "🚫 Certificate secret $CR_C_SECRET_NAME not found in $ISSUER_NAMESPACE. Test failed."
    exit 1
}

delete_issuer_specification_field() {
    local field_name=$1
    local issuer_or_cluster_issuer=$2

    local target=$ISSUER_CRD_FQTN
    if [[ $issuer_or_cluster_issuer == "ClusterIssuer" ]]; then
        target=$CLUSTER_ISSUER_CRD_FQTN
    fi

    echo "Deleting $target specification field: $field_name"

    kubectl -n "$ISSUER_NAMESPACE" patch $target $ISSUER_CR_NAME --type='json' -p="[{\"op\": \"remove\", \"path\": \"/spec/$field_name\"}]"

    if [ $? -ne 0 ]; then
        echo "⚠️ Failed to delete issuer specification field: $field_name"
        return 1
    fi

    echo "✅ Issuer specification field deleted successfully."
}

add_issuer_specification_field() {
    local field_name=$1
    local field_value=$2
    local issuer_or_cluster_issuer=$3

    local target=$ISSUER_CRD_FQTN
    if [[ $issuer_or_cluster_issuer == "ClusterIssuer" ]]; then
        target=$CLUSTER_ISSUER_CRD_FQTN
    fi

    echo "Adding $target specification field: $field_name with value: $field_value"

    kubectl -n "$ISSUER_NAMESPACE" patch $target $ISSUER_CR_NAME --type='json' -p="[{\"op\": \"add\", \"path\": \"/spec/$field_name\", \"value\": $field_value}]"

    echo "✅ Issuer specification field added successfully."
}

annotate_certificate_request() {
    local annotation_key=$1
    local annotation_value=$2

    echo "Annotating certificate request with $annotation_key: $annotation_value"

    kubectl -n "$ISSUER_NAMESPACE" annotate certificaterequest/$CR_CR_NAME "$annotation_key"="$annotation_value" --overwrite

    if [ $? -ne 0 ]; then
        echo "⚠️ Failed to annotate certificate request with $annotation_key"
        return 1
    fi

    echo "✅ Certificate request annotated successfully."
}

regenerate_issuer() {
    echo "🔄 Regenerating issuer..."
    delete_issuers
    create_issuer

    # Run health check on issuer
    echo "🔍 Checking issuer health..."
    kubectl -n ${ISSUER_NAMESPACE} wait --for=condition=Ready $ISSUER_CRD_FQTN/$ISSUER_CR_NAME --timeout=60s
    echo "✅ Issuer is healthy and ready for requests."
}

regenerate_cluster_issuer() {
    echo "🔄 Regenerating cluster issuer..."
    delete_issuers
    create_cluster_issuer

    # Run health check on issuer
    echo "🔍 Checking cluster issuer health..."
    kubectl -n ${ISSUER_NAMESPACE} wait --for=condition=Ready $CLUSTER_ISSUER_CRD_FQTN/$ISSUER_CR_NAME --timeout=60s
    echo "✅ ClusterIssuer is healthy and ready for requests."
}

check_for_certificates() {
    # check the certs directory for any files other than .gitkeep
    if [ -n "$(ls -A $CA_CERTS_PATH 2>/dev/null | grep -v '.gitkeep')" ]; then
        echo "✅ Certificates found in $CA_CERTS_PATH directory."
        return 0
    fi

    echo "⚠️ No certificates found in $CA_CERTS_PATH directory. May result in test failures."
}

create_ca_secret () {
   echo "🔐 Creating CA secret resource..."

   check_for_certificates

   kubectl -n ${MANAGER_NAMESPACE} create secret generic $SIGNER_CA_SECRET_NAME --from-literal=ca.crt="$(
    find e2e/certs -type f ! -name '.gitignore' -exec cat {} \;
  )" \
  --dry-run=client -o yaml | kubectl apply -f -

   echo "✅ CA secret '$SIGNER_CA_SECRET_NAME' created successfully"
}

delete_ca_secret() {
    echo "🗑️ Deleting CA secret..."

    kubectl -n ${MANAGER_NAMESPACE} delete secret $SIGNER_CA_SECRET_NAME || true

    echo "✅ CA secret '$SIGNER_CA_SECRET_NAME' deleted successfully"
}

regenerate_ca_secret() {
    echo "🔄 Regenerating CA secret..."

    delete_ca_secret
    create_ca_secret

    echo "✅ CA secret regenerated successfully"
}

add_bad_cert_to_ca_secret() {
    echo "🔐 Adding bad certificate to CA secret..."

    kubectl -n ${MANAGER_NAMESPACE} patch secret $SIGNER_CA_SECRET_NAME\
  --type='json' \
  -p='[
    {
      "op": "add",
      "path": "/data/zzz.crt",
      "value": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tClRISVNfSVNfTk9UX0FfUkVBTF9DRVJUCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K" 
    }
  ]'

    echo "✅ Bad certificate added to CA secret successfully."
}

create_ca_config_map() {
    echo "🔐 Creating CA config map resource..."
    
    check_for_certificates
    
    kubectl -n ${MANAGER_NAMESPACE} create configmap $SIGNER_CA_CONFIGMAP_NAME --from-literal=ca.crt="$(
        find e2e/certs -type f ! -name '.gitignore' -exec cat {} \;
      )" \
      --dry-run=client -o yaml | kubectl apply -f -
    
    echo "✅ CA config map '$SIGNER_CA_CONFIGMAP_NAME' created successfully"
}

delete_ca_config_map() {
    echo "🗑️ Deleting CA config map..."

    kubectl -n ${MANAGER_NAMESPACE} delete configmap $SIGNER_CA_CONFIGMAP_NAME || true

    echo "✅ CA config map '$SIGNER_CA_CONFIGMAP_NAME' deleted successfully"
}

regenerate_ca_config_map() {
    echo "🔄 Regenerating CA config map..."

    delete_ca_config_map
    create_ca_config_map

    echo "✅ CA config map regenerated successfully"
}

add_bad_cert_to_ca_config_map() {
    echo "🔐 Adding bad certificate to CA config map..."

    kubectl -n ${MANAGER_NAMESPACE} patch configmap $SIGNER_CA_CONFIGMAP_NAME\
  --type='json' \
  -p='[
    {
      "op": "add",
      "path": "/data/zzz.crt",
      "value": "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tClRISVNfSVNfTk9UX0FfUkVBTF9DRVJUCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K" 
    }
  ]'

    echo "✅ Bad certificate added to CA config map successfully."
}


# ================= BEGIN: Resource Deployment =====================

check_env

# Move the execution context to the parent directory
cd ..

echo "⚙️ Local image deployment: ${IS_LOCAL_DEPLOYMENT}"
echo "⚙️ Local Helm chart: ${IS_LOCAL_HELM}"

# Use existing kubeconfig context (set USE_MINIKUBE=true to use minikube)
if [ "${USE_MINIKUBE:-false}" = "true" ]; then
    if ! minikube status &> /dev/null; then
        echo "Error: Minikube is not running. Please start it with 'minikube start'"
        exit 1
    fi
    kubectl config use-context minikube
    echo "📡 Connecting to Minikube Docker environment..."
    eval $(minikube docker-env)
else
    echo "📡 Using current kubeconfig context..."
fi
echo "Connected to Kubernetes context: $(kubectl config current-context)..."
echo "🚀 Starting deployment..."

# 2. Deploy cert-manager Helm chart if not exists
echo "🔐 Checking for cert-manager installation..."
if ! helm_exists $CERT_MANAGER_NAMESPACE cert-manager; then
    install_cert_manager
else
    echo "✅ cert-manager already installed"
fi

# 2a. If cert-manager webhook certificate is out of date, redeploy it to update the certificate.
check_cert_manager_webhook_cert || deploy_cert_manager

# 3. Create command-cert-manager-issuer namespace if it doesn't exist
kubectl create namespace ${MANAGER_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# 4. Build the command-cert-manager-issuer Docker image
# This step is only needed if the image tag is "local"
if [ "$IS_LOCAL_DEPLOYMENT" = "true" ]; then
    if [ "${USE_MINIKUBE:-false}" != "true" ]; then
        echo "⚠️  WARNING: Local deployment without minikube requires pushing the image to a registry."
        echo "⚠️  Set IMAGE_REGISTRY env var to push, or use a published IMAGE_TAG instead."
    fi
    echo "🐳 Building ${FULL_IMAGE_NAME} Docker image..."
    docker build -t ${FULL_IMAGE_NAME} .
    echo "✅ Docker image built successfully"

    # If IMAGE_REGISTRY is set, push the image
    if [ -n "${IMAGE_REGISTRY:-}" ]; then
        REMOTE_IMAGE="${IMAGE_REGISTRY}/${IMAGE_NAME}:${IMAGE_TAG}"
        echo "📤 Tagging and pushing image to ${REMOTE_IMAGE}..."
        docker tag ${FULL_IMAGE_NAME} ${REMOTE_IMAGE}
        docker push ${REMOTE_IMAGE}
        FULL_IMAGE_NAME="${REMOTE_IMAGE}"
        echo "✅ Image pushed successfully"
    fi

    echo "📦 Listing Docker images..."
    docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.CreatedAt}}\t{{.Size}}" | head -5
fi

# 5. Deploy the command-cert-manager-issuer Helm chart if not exists
echo "🎛️  Checking for $IMAGE_NAME installation..."

# Check if the helm release exists. If so, destroy it. This ensures our Helm chart is always up to date.
if helm_exists $MANAGER_NAMESPACE $IMAGE_NAME; then
    echo "💣 Uninstalling $IMAGE_NAME..."
    helm uninstall $IMAGE_NAME -n ${MANAGER_NAMESPACE}
fi

install_cert_manager_issuer

# Find the deployment name (assuming it follows a pattern)
DEPLOYMENT_NAME=$(kubectl get deployments -n ${MANAGER_NAMESPACE} -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "$IMAGE_NAME")

if kubectl get deployment ${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE} >/dev/null 2>&1; then
    # Patch the deployment
    kubectl patch deployment ${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE} -p "{
        \"spec\": {
            \"template\": {
                \"spec\": {
                    \"containers\": [{
                        \"name\": \"${IMAGE_NAME}\",
                        \"image\": \"${FULL_IMAGE_NAME}\",
                        \"imagePullPolicy\": \"Never\"
                    }]
                }
            }
        }
    }"
    
    # Rollout deployment changes and apply the patch
    kubectl rollout restart deployment/${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE}
    kubectl rollout status deployment/${DEPLOYMENT_NAME} -n ${MANAGER_NAMESPACE} --timeout=300s

    
    echo "✅ Deployment patched and rolled out successfully"
else
    echo "⚠️  Deployment ${DEPLOYMENT_NAME} not found. The Helm chart might use a different naming convention."
    echo "Available deployments in ${MANAGER_NAMESPACE}:"
    kubectl get deployments -n ${MANAGER_NAMESPACE}
fi

echo ""
echo "🎉 Deployment complete!"
echo ""

# Delete stray CertificateRequest resources from previous runs
delete_certificate_request
echo ""

echo """🔐 Creating CA secret used for testing..."
regenerate_ca_secret
regenerate_ca_config_map
echo ""

# Deploy Issuer
echo "🔐 Deploying $ISSUER_NAMESPACE namespace if not exists..."
kubectl create namespace ${ISSUER_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -
regenerate_issuer
echo "✅ $ISSUER_NAMESPACE namespace is ready"
echo ""


echo ""
echo "✅ Resource deployment completed. Ready to start running tests!"
# ================= END: Resource Deployment =====================
#
#
#
#
#
#
#
#
# ================= BEGIN: Test Execution ========================
echo "🚀 Running E2E tests..."
echo ""

## ===================  BEGIN: Issuer & ClusterIssuer Tests    ============================

echo "🧪💬 Test 1: A generated certificate request should be successfully issued by Issuer."
regenerate_issuer
regenerate_certificate Issuer
wait_for_certificate_request
approve_certificate_request
check_certificate_request_status
check_for_certificate_secret
echo "🧪✅ Test 1 completed successfully."
echo ""

echo "🧪💬 Test 1a: A generated certificate request should be successfully issued by ClusterIssuer."
regenerate_cluster_issuer
regenerate_certificate ClusterIssuer
wait_for_certificate_request
approve_certificate_request
check_certificate_request_status
check_for_certificate_secret
echo "🧪✅ Test 1a completed successfully."
echo ""

echo "🧪💬 Test 2: Add EnrollmentPatternId to Issuer resource"
regenerate_issuer
delete_issuer_specification_field certificateTemplate Issuer
add_issuer_specification_field enrollmentPatternId $ENROLLMENT_PATTERN_ID Issuer
regenerate_certificate_request Issuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 2 completed successfully."
echo ""

echo "🧪💬 Test 2a: Add EnrollmentPatternId to ClusterIssuer resource"
regenerate_cluster_issuer
delete_issuer_specification_field certificateTemplate ClusterIssuer
add_issuer_specification_field enrollmentPatternId $ENROLLMENT_PATTERN_ID ClusterIssuer
regenerate_certificate_request ClusterIssuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 2a completed successfully."
echo ""

echo "🧪💬 Test 3: Add EnrollmentPatternName to Issuer resource"
regenerate_issuer
delete_issuer_specification_field certificateTemplate Issuer
add_issuer_specification_field enrollmentPatternName "$ENROLLMENT_PATTERN_NAME" Issuer
regenerate_certificate_request Issuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 3 completed successfully."
echo ""

echo "🧪💬 Test 3a: Add EnrollmentPatternName to ClusterIssuer resource"
regenerate_cluster_issuer
delete_issuer_specification_field certificateTemplate ClusterIssuer
add_issuer_specification_field enrollmentPatternName "$ENROLLMENT_PATTERN_NAME" ClusterIssuer
regenerate_certificate_request ClusterIssuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 3a completed successfully."
echo ""

echo "🧪💬 Test 4: Add OwnerRoleId to Issuer resource"
regenerate_issuer
add_issuer_specification_field ownerRoleId "$OWNER_ROLE_ID" Issuer
regenerate_certificate_request Issuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 4 completed successfully."
echo ""

echo "🧪💬 Test 4a: Add OwnerRoleId to ClusterIssuer resource"
regenerate_cluster_issuer
add_issuer_specification_field ownerRoleId "$OWNER_ROLE_ID" ClusterIssuer
regenerate_certificate_request ClusterIssuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 4a completed successfully."
echo ""

echo "🧪💬 Test 5: Add OwnerRoleName to Issuer resource"
regenerate_issuer
add_issuer_specification_field ownerRoleName "$OWNER_ROLE_NAME" Issuer
regenerate_certificate_request Issuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 5 completed successfully."
echo ""

echo "🧪💬 Test 5a: Add OwnerRoleName to ClusterIssuer resource"
regenerate_cluster_issuer
add_issuer_specification_field ownerRoleName "$OWNER_ROLE_NAME" ClusterIssuer
regenerate_certificate_request ClusterIssuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 5a completed successfully."
echo ""

echo "🧪💬 Test 6: Adding OwnerRoleId and OwnerRoleName to Issuer will have OwnerRoleId take precedence"
regenerate_issuer
add_issuer_specification_field ownerRoleId "$OWNER_ROLE_ID" Issuer
add_issuer_specification_field ownerRoleName "SomeRandomRoleName" Issuer
regenerate_certificate_request Issuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 6 completed successfully."
echo ""

## ===================  END: Issuer & ClusterIssuer Tests    ============================

## ===================  BEGIN: Annotation Tests    ============================

echo "🧪💬 Test 100: Annotate CertificateRequest with certificateTemplate"
regenerate_issuer
delete_issuer_specification_field certificateTemplate Issuer
add_issuer_specification_field certificateTemplate "SomeDefaultTemplate" Issuer # This is a placeholder, will be overridden by annotation
regenerate_certificate_request Issuer
annotate_certificate_request "command-issuer.keyfactor.com/certificateTemplate" "$CERTIFICATE_TEMPLATE"
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 100 completed successfully."
echo ""

echo "🧪💬 Test 101: Annotate CertificateRequest with enrollmentPatternId"
regenerate_issuer
delete_issuer_specification_field certificateTemplate Issuer
add_issuer_specification_field enrollmentPatternId 12345678 Issuer # This is a placeholder, will be overridden by annotation
regenerate_certificate_request Issuer
annotate_certificate_request "command-issuer.keyfactor.com/enrollmentPatternId" "$ENROLLMENT_PATTERN_ID"
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 101 completed successfully."
echo ""

echo "🧪💬 Test 102: Annotate CertificateRequest with enrollmentPatternName"
regenerate_issuer
delete_issuer_specification_field certificateTemplate Issuer
add_issuer_specification_field enrollmentPatternName "SomeDefaultPattern" Issuer # This is a placeholder, will be overridden by annotation
regenerate_certificate_request Issuer
annotate_certificate_request "command-issuer.keyfactor.com/enrollmentPatternName" "$ENROLLMENT_PATTERN_NAME"
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 102 completed successfully."
echo ""

echo "🧪💬 Test 103: Annotate CertificateRequest with ownerRoleId"
regenerate_issuer
add_issuer_specification_field ownerRoleId 12345678 Issuer # This is a placeholder, will be overridden by annotation
regenerate_certificate_request Issuer
annotate_certificate_request "command-issuer.keyfactor.com/ownerRoleId" "$OWNER_ROLE_ID"
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 103 completed successfully."
echo ""

echo "🧪💬 Test 104: Annotate CertificateRequest with ownerRoleName"
regenerate_issuer
add_issuer_specification_field ownerRoleName "SomeDefaultName" Issuer # This is a placeholder, will be overridden by annotation
regenerate_certificate_request Issuer
annotate_certificate_request "command-issuer.keyfactor.com/ownerRoleName" "$OWNER_ROLE_NAME"
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 104 completed successfully."
echo ""

## ===================  END: Annotation Tests    ============================

## ===================  BEGIN: CA Secret / ConfigMap Tests    ============================

if [[ "$DISABLE_CA_CHECK" == "true" ]]; then
    echo "⚠️ Skipping CA Secret / ConfigMap Tests as DISABLE_CA_CHECK is set to true"
else
    echo "🧪💬 Test 200: Use Secret for CA Bundle"
    regenerate_issuer
    delete_issuer_specification_field caSecretName Issuer
    add_issuer_specification_field caSecretName "\"$SIGNER_CA_SECRET_NAME\"" Issuer
    regenerate_certificate_request Issuer
    approve_certificate_request
    check_certificate_request_status
    echo "🧪✅ Test 200 completed successfully."
    echo ""

    echo "🧪💬 Test 200a: Use Secret for CA Bundle ClusterIssuer"
    regenerate_cluster_issuer
    delete_issuer_specification_field caSecretName ClusterIssuer
    add_issuer_specification_field caSecretName "\"$SIGNER_CA_SECRET_NAME\"" ClusterIssuer
    regenerate_certificate_request ClusterIssuer
    approve_certificate_request
    check_certificate_request_status
    echo "🧪✅ Test 200a completed successfully."
    echo ""

    echo "🧪💬 Test 201: Use ConfigMap for CA Bundle"
    regenerate_issuer
    delete_issuer_specification_field caSecretName Issuer
    add_issuer_specification_field caBundleConfigMapName "\"$SIGNER_CA_CONFIGMAP_NAME\"" Issuer
    regenerate_certificate_request Issuer
    approve_certificate_request
    check_certificate_request_status
    echo "🧪✅ Test 201 completed successfully."
    echo ""

    echo "🧪💬 Test 201a: Use ConfigMap for CA Bundle ClusterIssuer"
    regenerate_cluster_issuer
    delete_issuer_specification_field caSecretName ClusterIssuer
    add_issuer_specification_field caBundleConfigMapName "\"$SIGNER_CA_CONFIGMAP_NAME\"" ClusterIssuer
    regenerate_certificate_request ClusterIssuer
    approve_certificate_request
    check_certificate_request_status
    echo "🧪✅ Test 201a completed successfully."
    echo ""

    echo "🧪💬 Test 202: Use Secret with CA Key"
    regenerate_issuer
    delete_issuer_specification_field caSecretName Issuer
    add_bad_cert_to_ca_secret
    add_issuer_specification_field caSecretName "\"$SIGNER_CA_SECRET_NAME\"" Issuer
    add_issuer_specification_field caBundleKey "\"ca.crt\"" Issuer
    regenerate_certificate_request Issuer
    approve_certificate_request
    check_certificate_request_status
    echo "🧪✅ Test 202 completed successfully."
    echo ""

    echo "🧪💬 Test 202a: Use Secret with CA Key ClusterIssuer"
    regenerate_cluster_issuer
    delete_issuer_specification_field caSecretName ClusterIssuer
    add_bad_cert_to_ca_secret
    add_issuer_specification_field caSecretName "\"$SIGNER_CA_SECRET_NAME\"" ClusterIssuer
    add_issuer_specification_field caBundleKey "\"ca.crt\"" ClusterIssuer
    regenerate_certificate_request ClusterIssuer
    approve_certificate_request
    check_certificate_request_status
    echo "🧪✅ Test 202a completed successfully."
    echo ""

    echo "🧪💬 Test 203: Use ConfigMap with CA Key"
    regenerate_issuer
    delete_issuer_specification_field caSecretName Issuer
    add_bad_cert_to_ca_config_map
    add_issuer_specification_field caBundleConfigMapName "\"$SIGNER_CA_CONFIGMAP_NAME\"" Issuer
    add_issuer_specification_field caBundleKey "\"ca.crt\"" Issuer
    regenerate_certificate_request Issuer
    approve_certificate_request
    check_certificate_request_status
    echo "🧪✅ Test 203 completed successfully."
    echo ""

    echo "🧪💬 Test 203a: Use ConfigMap with CA Key ClusterIssuer"
    regenerate_cluster_issuer
    delete_issuer_specification_field caSecretName ClusterIssuer
    add_bad_cert_to_ca_config_map
    add_issuer_specification_field caBundleConfigMapName "\"$SIGNER_CA_CONFIGMAP_NAME\"" ClusterIssuer
    add_issuer_specification_field caBundleKey "\"ca.crt\"" ClusterIssuer
    regenerate_certificate_request ClusterIssuer
    approve_certificate_request
    check_certificate_request_status
    echo "🧪✅ Test 203a completed successfully."
    echo ""
fi



echo "🎉🎉🎉 Tests have completed successfully!"

## ===================  END: CA Secret / ConfigMap Tests    ============================

# ================= END: Test Execution ========================