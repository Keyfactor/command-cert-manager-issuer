#!/bin/bash

## =======================   LICENSE     ===================================
# Copyright © 2025 Keyfactor
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

## ======================= Requirements ===================================
# - Minikube running
# - Helm installed
# - Docker installed
# - kubectl installed
# - cmctl installed
# - cert-manager Helm chart available
## ===========================================================================

## ======================= How to run ===================================
# Enable the script to run:
# > chmod +x run_tests.sh
# Load the environment variables:
# > source .env
# Run the tests:
# > ./run_tests.sh
## ===========================================================================


IMAGE_REPO="keyfactor"
IMAGE_NAME="command-cert-manager-issuer"
# IMAGE_TAG="2.2.0-rc.9" # Uncomment if you want to use an existing image from the repository
IMAGE_TAG="local" # Uncomment if you want to build the image locally
FULL_IMAGE_NAME="${IMAGE_REPO}/${IMAGE_NAME}:${IMAGE_TAG}"

HELM_CHART_NAME="command-cert-manager-issuer"
#HELM_CHART_VERSION="2.1.0" # Uncomment if you want to use a specific version from the Helm repository
HELM_CHART_VERSION="local" # Uncomment if you want to use the local Helm chart

IS_LOCAL_DEPLOYMENT=$([ "$IMAGE_TAG" = "local" ] && echo "true" || echo "false")
IS_LOCAL_HELM=$([ "$HELM_CHART_VERSION" = "local" ] && echo "true" || echo "false")

# TODO: Handle both in the e2e tests
ISSUER_TYPE="Issuer"
CLUSTER_ISSUER_TYPE="ClusterIssuer"

#ISSUER_OR_CLUSTER_ISSUER="ClusterIssuer"
ISSUER_OR_CLUSTER_ISSUER="Issuer"
ISSUER_CR_NAME="issuer"
ISSUER_CRD_FQTN="issuers.command-issuer.keyfactor.com"
CLUSTER_ISSUER_CRD_FQTN="clusterissuers.command-issuer.keyfactor.com"

ENROLLMENT_PATTERN_ID=1
ENROLLMENT_PATTERN_NAME="Test Enrollment Pattern"

CHART_PATH="./deploy/charts/command-cert-manager-issuer"

CERT_MANAGER_VERSION="v1.17.0"

MANAGER_NAMESPACE="command-issuer-system"
CERT_MANAGER_NAMESPACE="cert-manager"
ISSUER_NAMESPACE="issuer-playground"

SIGNER_SECRET_NAME="auth-secret"
SIGNER_CA_SECRET_NAME="ca-secret"

CERTIFICATEREQUEST_CRD_FQTN="certificaterequests.cert-manager.io"


CR_CR_NAME="req"

set -e # Exit on any error

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

check_env() {
    validate_env_present HOSTNAME true
    validate_env_present API_PATH true
    validate_env_present CERTIFICATE_TEMPLATE true
    validate_env_present CERTIFICATE_AUTHORITY_LOGICAL_NAME true
    validate_env_present OAUTH_TOKEN_URL true
    validate_env_present OAUTH_CLIENT_ID true
    validate_env_present OAUTH_CLIENT_SECRET true

    validate_env_present CERTIFICATE_AUTHORITY_HOSTNAME false
}

ns_exists () {
    local ns=$1
    if [ "$(kubectl get namespace -o json | jq --arg namespace "$ns" -e '.items[] | select(.metadata.name == $namespace) | .metadata.name')" ]; then
        return 0
    fi
    return 1
}

helm_exists () {
    local namespace=$1
    local chart_name=$2
    if helm list -n "$namespace" | grep -q "$chart_name"; then
        return 0
    fi
    return 1
}

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

secret_exists () {
    local ns=$1
    local name=$2
    if [ "$(kubectl -n "$ns" get secret -o json | jq --arg name "$name" -e '.items[] | select(.metadata.name == $name) | .metadata.name')" ]; then
        echo "secret exists called $name in $ns"
        return 0
    fi
    return 1
}

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
        CHART_PATH="command-issuer/command-cert-manager-issuer"
        echo "Using Helm chart from repository for version ${HELM_CHART_VERSION}: $CHART_PATH..."
        VERSION_PARAM="--version ${HELM_CHART_VERSION}"
    fi

    # Only set the image repository parameter if we are deploying locally
    if [[ "$IS_LOCAL_DEPLOYMENT" == "true" ]]; then
        IMAGE_REPO_PARAM="--set image.repository=${IMAGE_NAME}"
    else
        IMAGE_REPO_PARAM=""
    fi
    
    # Helm chart could be out of date for release candidates, so we will install from
    # the chart defined in the repository.
    helm install $IMAGE_NAME ${CHART_PATH} \
        --namespace ${MANAGER_NAMESPACE} \
        $VERSION_PARAM \
        $IMAGE_REPO_PARAM \
        --set "fullnameOverride=${IMAGE_NAME}" \
        --set image.tag=${IMAGE_TAG} \
        --set image.pullPolicy=Never \
        --wait
        
    echo "✅ $IMAGE_NAME installed successfully"
}

create_issuer() {
    echo "🔐 Creating issuer resources..."

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

    kubectl -n "$ISSUER_NAMESPACE" apply -f - <<EOF
apiVersion: command-issuer.keyfactor.com/v1alpha1
kind: $ISSUER_OR_CLUSTER_ISSUER
metadata:
  name: "$ISSUER_CR_NAME"
spec:
  hostname: "$HOSTNAME"
  apiPath: "$API_PATH"
  commandSecretName: "$SIGNER_SECRET_NAME"
  certificateTemplate: "$CERTIFICATE_TEMPLATE"
  certificateAuthorityLogicalName: "$CERTIFICATE_AUTHORITY_LOGICAL_NAME"
  certificateAuthorityHostname: "$CERTIFICATE_AUTHORITY_HOSTNAME"
EOF


    echo "✅ Issuer resources created successfully"
}

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

create_certificate_request() {
    local issuer_type=$1

    echo "Generating a certificate request for issuer type: $issuer_type"

    openssl req -new \
                -newkey rsa:2048 \
                -nodes \
                -keyout random.key \
                -out random.csr \
                -subj "/CN=$(openssl rand -hex 12)" > /dev/null 2>&1

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

regenerate_certificate_request() {
    local issuer_type=$1
    delete_certificate_request
    create_certificate_request $issuer_type 
}

approve_certificate_request() {
    echo "🔍 Approving certificate request..."

    if cr_exists $CERTIFICATEREQUEST_CRD_FQTN "$ISSUER_NAMESPACE" "$CR_CR_NAME"; then
        cmctl -n $ISSUER_NAMESPACE approve $CR_CR_NAME
        echo "Certificate request approved successfully."
    else
        echo "⚠️ CertificateRequest $CR_CR_NAME not found in $ISSUER_NAMESPACE"
    fi
}

check_certificate_request_status() {
    echo "🔎 Checking certificate request status..."

    if [[ ! $(kubectl wait --for=condition=Ready certificaterequest/$CR_CR_NAME -n $ISSUER_NAMESPACE --timeout=30s) ]]; then
        echo "⚠️  Certificate request did not become ready within the timeout period."
        echo "Check the Issuer / Command Issuer logs for errors. Check the configuration of your Issuer or CertificateRequest resources."
        echo "🚫 Test failed"
        exit 1
    fi

    echo "✅ Certificate request was issued successfully."
}

delete_issuer_specification_field() {
    local field_name=$1

    echo "Deleting issuer specification field: $field_name"

    kubectl -n "$ISSUER_NAMESPACE" patch $ISSUER_CRD_FQTN $ISSUER_CR_NAME --type='json' -p="[{\"op\": \"remove\", \"path\": \"/spec/$field_name\"}]"

    if [ $? -ne 0 ]; then
        echo "⚠️ Failed to delete issuer specification field: $field_name"
        return 1
    fi

    echo "✅ Issuer specification field deleted successfully."
}

add_issuer_specification_field() {
    local field_name=$1
    local field_value=$2

    echo "Adding issuer specification field: $field_name with value: $field_value"

    resolved_value=""

    if [[ $field_value =~ ^[0-9]+$ ]]; then
        resolved_value=$field_value
    else
        resolved_value="\"$field_value\""
    fi

    kubectl -n "$ISSUER_NAMESPACE" patch $ISSUER_CRD_FQTN $ISSUER_CR_NAME --type='json' -p="[{\"op\": \"add\", \"path\": \"/spec/$field_name\", \"value\": $field_value}]"

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



# ================= BEGIN: Resource Deployment =====================

check_env

# Move the execution context to the parent directory
cd ..

echo "⚙️ Local image deployment: ${IS_LOCAL_DEPLOYMENT}"
echo "⚙️ Local Helm chart: ${IS_LOCAL_HELM}"

if ! minikube status &> /dev/null; then
    echo "Error: Minikube is not running. Please start it with 'minikube start'"
    exit 1
fi

kubectl config use-context minikube
echo "Connected to Kubernetes context: $(kubectl config current-context)..."

# 1. Connect to minikube Docker env
echo "📡 Connecting to Minikube Docker environment..."
eval $(minikube docker-env)
echo "🚀 Starting deployment to Minikube..."

# 2. Deploy cert-manager Helm chart if not exists
echo "🔐 Checking for cert-manager installation..."
if ! helm_exists $CERT_MANAGER_NAMESPACE cert-manager; then
    install_cert_manager
else
    echo "✅ cert-manager already installed"
fi

# 3. Create command-cert-manager-issuer namespace if it doesn't exist
kubectl create namespace ${MANAGER_NAMESPACE} --dry-run=client -o yaml | kubectl apply -f -

# 4. Build the command-cert-manager-issuer Docker image
# This step is only needed if the image tag is "local"
if "$IS_LOCAL_DEPLOYMENT" = "true"; then
    echo "🐳 Building ${FULL_IMAGE_NAME} Docker image..."
    docker build -t ${FULL_IMAGE_NAME} .
    echo "✅ Docker image built successfully"
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

echo "🧪💬 Test 1: A generated certificate request should be successfully issued by Issuer."
regenerate_issuer
regenerate_certificate_request Issuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 1 completed successfully."
echo ""

echo "🧪💬 Test 2: Add EnrollmentPatternId to Issuer resource"
regenerate_issuer
delete_issuer_specification_field certificateTemplate
add_issuer_specification_field enrollmentPatternId $ENROLLMENT_PATTERN_ID
regenerate_certificate_request Issuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 2 completed successfully."
echo ""

echo "🧪💬 Test 3: Add EnrollmentPatternName to Issuer resource"
regenerate_issuer
delete_issuer_specification_field certificateTemplate
add_issuer_specification_field enrollmentPatternName "$ENROLLMENT_PATTERN_NAME"
regenerate_certificate_request Issuer
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 3 completed successfully."
echo ""

echo "🧪💬 Test 4: Annotate CertificateRequest with certificateTemplate"
regenerate_issuer
delete_issuer_specification_field certificateTemplate
add_issuer_specification_field certificateTemplate "SomeDefaultTemplate" # This is a placeholder, will be overridden by annotation
regenerate_certificate_request Issuer
annotate_certificate_request "command-issuer.keyfactor.com/certificateTemplate" "$CERTIFICATE_TEMPLATE"
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 4 completed successfully."
echo ""

echo "🧪💬 Test 5: Annotate CertificateRequest with enrollmentPatternId"
regenerate_issuer
delete_issuer_specification_field certificateTemplate
add_issuer_specification_field enrollmentPatternId 12345678 # This is a placeholder, will be overridden by annotation
regenerate_certificate_request Issuer
annotate_certificate_request "command-issuer.keyfactor.com/enrollmentPatternId" "$ENROLLMENT_PATTERN_ID"
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 5 completed successfully."
echo ""

echo "🧪💬 Test 6: Annotate CertificateRequest with enrollmentPatternName"
regenerate_issuer
delete_issuer_specification_field certificateTemplate
add_issuer_specification_field enrollmentPatternName "SomeDefaultPattern" # This is a placeholder, will be overridden by annotation
regenerate_certificate_request Issuer
annotate_certificate_request "command-issuer.keyfactor.com/enrollmentPatternName" "$ENROLLMENT_PATTERN_NAME"
approve_certificate_request
check_certificate_request_status
echo "🧪✅ Test 6 completed successfully."
echo ""

echo "🎉🎉🎉 Tests have completed successfully!"

# ================= END: Test Execution ========================