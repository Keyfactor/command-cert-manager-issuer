<a href="https://kubernetes.io">
    <img src="https://raw.githubusercontent.com/cert-manager/cert-manager/d53c0b9270f8cd90d908460d69502694e1838f5f/logo/logo-small.png" alt="Terraform logo" title="K8s" align="left" height="50" />
</a>

# Installing the Keyfactor Command Issuer for cert-manager

[![Go Report Card](https://goreportcard.com/badge/github.com/Keyfactor/command-cert-manager-issuer)](https://goreportcard.com/report/github.com/Keyfactor/command-cert-manager-issuer)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://img.shields.io/badge/License-Apache%202.0-blue.svg)

### Documentation Tree
* [Usage](config_usage.markdown)
* [Example Usage](example.markdown)
* [Customization](annotations.markdown)
* [Testing the Source](testing.markdown)

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

Before starting, ensure that all of the above requirements are met, and that Keyfactor Command is properly configured according to the [product docs](https://software.keyfactor.com/Content/MasterTopics/Home.htm). Additionally, verify that at least one Kubernetes node is running by running the following command:

```shell
kubectl get nodes
```

A static installation of cert-manager can be installed with the following command:
    
```shell
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.11.0/cert-manager.yaml
```

###### :pushpin: Running the static cert-manager configuration is not recommended for production use. For more information, see [Installing cert-manager](https://cert-manager.io/docs/installation/).

### Installation from Helm Chart [recommended]

The cert-manager external issuer for Keyfactor Command is installed using a Helm chart. The chart is available in the [Command cert-manager Helm repository](https://keyfactor.github.io/command-cert-manager-issuer/).

1. Add the Helm repository:
    
    ```shell
    helm repo add command-issuer https://keyfactor.github.io/command-cert-manager-issuer
    helm repo update
    ```

2. Then, install the chart:
    
    ```shell
    helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer \
        --namespace command-issuer-system \
        --create-namespace \
        --set crd.create=true
    ```

    1. Modifications can be made by overriding the default values in the `values.yaml` file with the `--set` flag. For example, to override the `secretConfig.useClusterRoleForSecretAccess` to configure the chart to use a cluster role for secret access, run the following command:

        ```shell
        helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer \
            --namespace command-issuer-system \
            --create-namespace \
            --set crd.create=true \
            --set secretConfig.useClusterRoleForSecretAccess=true
        ```

    2. Modifications can also be made by modifying the `values.yaml` file directly. For example, to override the `secretConfig.useClusterRoleForSecretAccess` value to configure the chart to use a cluster role for secret access, modify the `secretConfig.useClusterRoleForSecretAccess` value in the `values.yaml` file by creating an override file:

        ```yaml
        cat <<EOF > override.yaml
        secretConfig:
            useClusterRoleForSecretAccess: true
        EOF
        ```

        Then, use the `-f` flag to specify the `values.yaml` file:

        ```shell
        helm install command-cert-manager-issuer command-issuer/command-cert-manager-issuer \
            --namespace command-issuer-system \
            -f override.yaml
        ```

### Installation from Manifests

The cert-manager external issuer for Keyfactor Command can be installed using the manifests in the `config/` directory.

1. Install the custom resource definitions (CRDs) for the cert-manager external issuer for Keyfactor Command:

    ```shell
    make install
    ```

2. Finally, deploy the controller to the cluster:

    ```shell
    make deploy DOCKER_REGISTRY=<your container registry> DOCKER_IMAGE_NAME=keyfactor/command-cert-manager-issuer VERSION=<tag>
    ```

Next, complete the [Usage](config_usage.markdown) steps to configure the cert-manager external issuer for Keyfactor Command.
