/*
Copyright 2023 The Keyfactor Command Authors.

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

package util

import (
	"errors"
	"fmt"
	"os"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commandissuer "github.com/Keyfactor/command-issuer/api/v1alpha1"
)

const inClusterNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"

func GetSpecAndStatus(issuer client.Object) (*commandissuer.IssuerSpec, *commandissuer.IssuerStatus, error) {
	switch t := issuer.(type) {
	case *commandissuer.Issuer:
		return &t.Spec, &t.Status, nil
	case *commandissuer.ClusterIssuer:
		return &t.Spec, &t.Status, nil
	default:
		return nil, nil, fmt.Errorf("not an issuer type: %t", t)
	}
}

func SetReadyCondition(status *commandissuer.IssuerStatus, conditionStatus commandissuer.ConditionStatus, reason, message string) {
	ready := GetReadyCondition(status)
	if ready == nil {
		ready = &commandissuer.IssuerCondition{
			Type: commandissuer.IssuerConditionReady,
		}
		status.Conditions = append(status.Conditions, *ready)
	}
	if ready.Status != conditionStatus {
		ready.Status = conditionStatus
		now := metav1.Now()
		ready.LastTransitionTime = &now
	}
	ready.Reason = reason
	ready.Message = message

	for i, c := range status.Conditions {
		if c.Type == commandissuer.IssuerConditionReady {
			status.Conditions[i] = *ready
			return
		}
	}
}

func GetReadyCondition(status *commandissuer.IssuerStatus) *commandissuer.IssuerCondition {
	for _, c := range status.Conditions {
		if c.Type == commandissuer.IssuerConditionReady {
			return &c
		}
	}
	return nil
}

func IsReady(status *commandissuer.IssuerStatus) bool {
	if c := GetReadyCondition(status); c != nil {
		return c.Status == commandissuer.ConditionTrue
	}
	return false
}

var ErrNotInCluster = errors.New("not running in-cluster")

// Copied from controller-runtime/pkg/leaderelection
func GetInClusterNamespace() (string, error) {
	// Check whether the namespace file exists.
	// If not, we are not running in cluster so can't guess the namespace.
	_, err := os.Stat(inClusterNamespacePath)
	if os.IsNotExist(err) {
		return "", ErrNotInCluster
	} else if err != nil {
		return "", fmt.Errorf("error checking namespace file: %w", err)
	}

	// Load the namespace file and return its content
	namespace, err := os.ReadFile(inClusterNamespacePath)
	if err != nil {
		return "", fmt.Errorf("error reading namespace file: %w", err)
	}
	return string(namespace), nil
}
