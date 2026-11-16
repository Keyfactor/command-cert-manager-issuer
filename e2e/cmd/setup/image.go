/*
Copyright © 2026 Keyfactor

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"strings"
)

// imageLoader is the way a locally built image gets onto a cluster's nodes.
type imageLoader int

const (
	// loaderNone means the cluster type is not recognized, so the image must be pushed to a registry.
	loaderNone imageLoader = iota
	loaderMinikube
	loaderKind
	// loaderSharedDaemon is a cluster that uses the local Docker daemon, so the build is already available.
	loaderSharedDaemon
)

func (l imageLoader) String() string {
	switch l {
	case loaderMinikube:
		return "minikube image load"
	case loaderKind:
		return "kind load docker-image"
	case loaderSharedDaemon:
		return "shared Docker daemon"
	default:
		return "none"
	}
}

// tool is the CLI the loader needs, beyond docker.
func (l imageLoader) tool() string {
	switch l {
	case loaderMinikube:
		return "minikube"
	case loaderKind:
		return "kind"
	default:
		return "docker"
	}
}

// imageLoaderFor guesses how to load an image from the kubeconfig context
// name, relying on the default context names these tools create. It also
// returns the minikube profile or kind cluster name where relevant.
func imageLoaderFor(kubeContext string) (imageLoader, string) {
	switch {
	case kubeContext == "minikube":
		return loaderMinikube, kubeContext
	case strings.HasPrefix(kubeContext, "kind-"):
		return loaderKind, strings.TrimPrefix(kubeContext, "kind-")
	case kubeContext == "docker-desktop":
		return loaderSharedDaemon, ""
	default:
		return loaderNone, ""
	}
}

func (l imageLoader) load(ctx context.Context, image, name string) error {
	var err error
	switch l {
	case loaderMinikube:
		_, err = execCmd(ctx, execOpts{stream: true}, "minikube", "image", "load", image, "-p", name)
	case loaderKind:
		_, err = execCmd(ctx, execOpts{stream: true}, "kind", "load", "docker-image", image, "--name", name)
	}
	return err
}
