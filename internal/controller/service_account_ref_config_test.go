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

package controller

import (
	"context"
	"testing"

	commandissuer "github.com/Keyfactor/command-cert-manager-issuer/api/v1alpha1"
	"github.com/Keyfactor/command-cert-manager-issuer/internal/command"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestServiceAccountRefFromIssuer(t *testing.T) {
	azure := &commandissuer.AzureIdentity{ClientID: "client", TenantID: "tenant"}
	gcp := &commandissuer.GCPIdentity{ServiceAccountEmail: "sa@example.iam.gserviceaccount.com"}

	namespaced := func(ref *commandissuer.ServiceAccountReference) commandissuer.IssuerLike {
		return &commandissuer.Issuer{ObjectMeta: metav1.ObjectMeta{Name: "i", Namespace: "tenant-a"}, Spec: commandissuer.IssuerSpec{ServiceAccountRef: ref}}
	}
	clusterScoped := func(ref *commandissuer.ServiceAccountReference) commandissuer.IssuerLike {
		return &commandissuer.ClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: "c"}, Spec: commandissuer.IssuerSpec{ServiceAccountRef: ref}}
	}

	tests := []struct {
		name     string
		issuer   commandissuer.IssuerLike
		expected *command.ServiceAccountRef
	}{
		{name: "nil-ref-namespaced", issuer: namespaced(nil), expected: nil},
		{name: "nil-ref-cluster", issuer: clusterScoped(nil), expected: nil},
		{
			// The command package must never receive an unresolved namespace.
			name:     "namespaced-omitted-namespace-defaults-to-the-issuers-own",
			issuer:   namespaced(&commandissuer.ServiceAccountReference{Name: "sa"}),
			expected: &command.ServiceAccountRef{Name: "sa", Namespace: "tenant-a"},
		},
		{
			name:     "namespaced-explicit-namespace-is-kept",
			issuer:   namespaced(&commandissuer.ServiceAccountReference{Name: "sa", Namespace: "tenant-a"}),
			expected: &command.ServiceAccountRef{Name: "sa", Namespace: "tenant-a"},
		},
		{
			name:     "cluster-scoped-keeps-its-explicit-namespace",
			issuer:   clusterScoped(&commandissuer.ServiceAccountReference{Name: "sa", Namespace: "tenant-b"}),
			expected: &command.ServiceAccountRef{Name: "sa", Namespace: "tenant-b"},
		},
		{
			// Cluster-scoped objects have no namespace to default to; validation rejects this earlier.
			name:     "cluster-scoped-omitted-namespace-stays-empty",
			issuer:   clusterScoped(&commandissuer.ServiceAccountReference{Name: "sa"}),
			expected: &command.ServiceAccountRef{Name: "sa"},
		},
		{
			name:     "azure-block-is-mapped",
			issuer:   namespaced(&commandissuer.ServiceAccountReference{Name: "sa", Provider: "azure", Azure: azure}),
			expected: &command.ServiceAccountRef{Name: "sa", Namespace: "tenant-a", Provider: "azure", Azure: &command.AzureIdentity{ClientID: "client", TenantID: "tenant"}},
		},
		{
			name:     "gcp-block-is-mapped",
			issuer:   namespaced(&commandissuer.ServiceAccountReference{Name: "sa", Provider: "gcp", GCP: gcp}),
			expected: &command.ServiceAccountRef{Name: "sa", Namespace: "tenant-a", Provider: "gcp", GCP: &command.GCPIdentity{ServiceAccountEmail: "sa@example.iam.gserviceaccount.com"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, serviceAccountRefFromIssuer(tc.issuer))
		})
	}

	t.Run("result-does-not-alias-the-spec", func(t *testing.T) {
		spec := &commandissuer.ServiceAccountReference{Name: "sa", Azure: &commandissuer.AzureIdentity{ClientID: "client"}}
		out := serviceAccountRefFromIssuer(namespaced(spec))
		out.Azure.ClientID = "changed"
		assert.Equal(t, "client", spec.Azure.ClientID)
	})
}

func TestCommandConfigFromIssuerServiceAccountRefConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, commandissuer.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	t.Run("ref-populates-the-config-and-its-dependencies", func(t *testing.T) {
		issuer := &commandissuer.Issuer{
			ObjectMeta: metav1.ObjectMeta{Name: "i", Namespace: "tenant-a"},
			Spec: commandissuer.IssuerSpec{
				Hostname:          "https://ca.example.com",
				ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa"},
			},
		}

		config, err := commandConfigFromIssuer(context.Background(), fakeClient, issuer, "kube-system", "default-tenant")

		require.NoError(t, err)
		assert.Equal(t, &command.ServiceAccountRef{Name: "sa", Namespace: "tenant-a"}, config.ServiceAccountRef)
		require.NotNil(t, config.WorkloadIdentity)
		assert.NotNil(t, config.WorkloadIdentity.Requester)
		assert.NotNil(t, config.WorkloadIdentity.Getter)
		assert.Equal(t, "default-tenant", config.WorkloadIdentity.DefaultAzureTenantID)
		assert.Nil(t, config.BasicAuth)
		assert.Nil(t, config.OAuth)
	})

	t.Run("no-ref-leaves-the-config-untouched", func(t *testing.T) {
		issuer := &commandissuer.Issuer{
			ObjectMeta: metav1.ObjectMeta{Name: "i", Namespace: "tenant-a"},
			Spec:       commandissuer.IssuerSpec{Hostname: "https://ca.example.com"},
		}

		config, err := commandConfigFromIssuer(context.Background(), fakeClient, issuer, "tenant-a", "default-tenant")

		require.NoError(t, err)
		assert.Nil(t, config.ServiceAccountRef)
		assert.Nil(t, config.WorkloadIdentity)
	})
}
