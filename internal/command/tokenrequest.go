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

package command

import (
	"context"
	"errors"
	"fmt"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// AzureTokenExchangeAudience is the audience Azure expects on a federated credential's
	// token for public-cloud Entra ID.
	AzureTokenExchangeAudience = "api://AzureADTokenExchange"

	// serviceAccountTokenTTL is the lifetime requested for a ServiceAccount token. It is the
	// minimum the Kubernetes API server accepts; the token is exchanged immediately and never held.
	serviceAccountTokenTTL = 10 * time.Minute
)

var errTokenRequestFailure = errors.New("failed to request a ServiceAccount token")

// TokenRequester mints short-lived tokens for a ServiceAccount through the Kubernetes
// TokenRequest API. It exists so callers can be tested without a cluster.
type TokenRequester interface {
	RequestToken(ctx context.Context, namespace, name string, audiences []string, ttl time.Duration) (string, error)
}

type kubeTokenRequester struct {
	client client.Client
}

var _ TokenRequester = &kubeTokenRequester{}

// NewTokenRequester returns a TokenRequester backed by the serviceaccounts/token subresource.
func NewTokenRequester(c client.Client) TokenRequester {
	return &kubeTokenRequester{client: c}
}

// RequestToken requests a token for the named ServiceAccount, valid only for the given audiences.
// An empty audience list is rejected: the API server would default it to its own audience and
// produce a token usable against the Kubernetes API.
func (k *kubeTokenRequester) RequestToken(ctx context.Context, namespace, name string, audiences []string, ttl time.Duration) (string, error) {
	if namespace == "" || name == "" {
		return "", fmt.Errorf("%w: namespace and name are required", errTokenRequestFailure)
	}
	if len(audiences) == 0 {
		return "", fmt.Errorf("%w: at least one audience is required", errTokenRequestFailure)
	}
	for _, a := range audiences {
		if a == "" {
			return "", fmt.Errorf("%w: audiences must not be empty", errTokenRequestFailure)
		}
	}

	expirationSeconds := int64(ttl / time.Second)
	request := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         audiences,
			ExpirationSeconds: &expirationSeconds,
		},
	}
	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
	}

	if err := k.client.SubResource("token").Create(ctx, serviceAccount, request); err != nil {
		return "", fmt.Errorf("%w: %s/%s: %w", errTokenRequestFailure, namespace, name, err)
	}
	if request.Status.Token == "" {
		return "", fmt.Errorf("%w: %s/%s: the API server returned an empty token", errTokenRequestFailure, namespace, name)
	}

	return request.Status.Token, nil
}
