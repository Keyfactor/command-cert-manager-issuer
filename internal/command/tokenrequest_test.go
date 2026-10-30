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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type tokenRequestCall struct {
	subResource string
	namespace   string
	name        string
	audiences   []string
	expiration  *int64
}

// newInterceptedClient returns a client whose TokenRequest subresource create is handled by fn.
// The controller-runtime fake client has no TokenRequest support of its own.
func newInterceptedClient(t *testing.T, fn func(call tokenRequestCall, request *authenticationv1.TokenRequest) error) (client.Client, *[]tokenRequestCall) {
	t.Helper()
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, authenticationv1.AddToScheme(scheme))

	var calls []tokenRequestCall
	c := fake.NewClientBuilder().WithScheme(scheme).WithInterceptorFuncs(interceptor.Funcs{
		SubResourceCreate: func(_ context.Context, _ client.Client, subResourceName string, obj client.Object, subResource client.Object, _ ...client.SubResourceCreateOption) error {
			request, ok := subResource.(*authenticationv1.TokenRequest)
			require.True(t, ok, "expected a TokenRequest")
			call := tokenRequestCall{
				subResource: subResourceName,
				namespace:   obj.GetNamespace(),
				name:        obj.GetName(),
				audiences:   request.Spec.Audiences,
				expiration:  request.Spec.ExpirationSeconds,
			}
			calls = append(calls, call)
			return fn(call, request)
		},
	}).Build()
	return c, &calls
}

func TestKubeTokenRequester(t *testing.T) {
	okHandler := func(_ tokenRequestCall, request *authenticationv1.TokenRequest) error {
		request.Status.Token = "minted-token"
		return nil
	}

	t.Run("requests-the-token-subresource-for-the-referenced-serviceaccount", func(t *testing.T) {
		c, calls := newInterceptedClient(t, okHandler)

		token, err := NewTokenRequester(c).RequestToken(context.Background(), "tenant-a", "sa", []string{AzureTokenExchangeAudience}, 10*time.Minute)

		require.NoError(t, err)
		assert.Equal(t, "minted-token", token)
		require.Len(t, *calls, 1)
		call := (*calls)[0]
		assert.Equal(t, "token", call.subResource)
		assert.Equal(t, "tenant-a", call.namespace)
		assert.Equal(t, "sa", call.name)
		assert.Equal(t, []string{AzureTokenExchangeAudience}, call.audiences)
		require.NotNil(t, call.expiration)
		assert.Equal(t, int64(600), *call.expiration)
	})

	t.Run("requested-audiences-are-passed-through-unchanged", func(t *testing.T) {
		c, calls := newInterceptedClient(t, okHandler)

		_, err := NewTokenRequester(c).RequestToken(context.Background(), "ns", "sa", []string{"aud-1", "aud-2"}, 10*time.Minute)

		require.NoError(t, err)
		assert.Equal(t, []string{"aud-1", "aud-2"}, (*calls)[0].audiences)
	})

	// An empty audience list makes the API server issue a token for its own audience, which is
	// valid against the Kubernetes API. It must never be sent.
	rejected := []struct {
		name      string
		namespace string
		sa        string
		audiences []string
	}{
		{name: "nil-audiences", namespace: "ns", sa: "sa", audiences: nil},
		{name: "empty-audiences", namespace: "ns", sa: "sa", audiences: []string{}},
		{name: "empty-string-audience", namespace: "ns", sa: "sa", audiences: []string{""}},
		{name: "empty-string-among-audiences", namespace: "ns", sa: "sa", audiences: []string{"ok", ""}},
		{name: "empty-namespace", namespace: "", sa: "sa", audiences: []string{"aud"}},
		{name: "empty-name", namespace: "ns", sa: "", audiences: []string{"aud"}},
	}
	for _, tc := range rejected {
		t.Run("rejects-"+tc.name+"-without-calling-the-api", func(t *testing.T) {
			c, calls := newInterceptedClient(t, okHandler)

			token, err := NewTokenRequester(c).RequestToken(context.Background(), tc.namespace, tc.sa, tc.audiences, 10*time.Minute)

			require.Error(t, err)
			assert.ErrorIs(t, err, errTokenRequestFailure)
			assert.Empty(t, token)
			assert.Empty(t, *calls, "no request may reach the API server")
		})
	}

	t.Run("api-error-is-wrapped-and-names-the-serviceaccount", func(t *testing.T) {
		forbidden := errors.New("serviceaccounts \"sa\" is forbidden")
		c, _ := newInterceptedClient(t, func(tokenRequestCall, *authenticationv1.TokenRequest) error { return forbidden })

		token, err := NewTokenRequester(c).RequestToken(context.Background(), "tenant-a", "sa", []string{"aud"}, 10*time.Minute)

		require.Error(t, err)
		assert.ErrorIs(t, err, errTokenRequestFailure)
		assert.ErrorIs(t, err, forbidden)
		assert.Contains(t, err.Error(), "tenant-a/sa")
		assert.Empty(t, token)
	})

	t.Run("empty-token-in-response-is-an-error", func(t *testing.T) {
		c, _ := newInterceptedClient(t, func(tokenRequestCall, *authenticationv1.TokenRequest) error { return nil })

		token, err := NewTokenRequester(c).RequestToken(context.Background(), "ns", "sa", []string{"aud"}, 10*time.Minute)

		require.Error(t, err)
		assert.ErrorIs(t, err, errTokenRequestFailure)
		assert.Empty(t, token)
	})
}
