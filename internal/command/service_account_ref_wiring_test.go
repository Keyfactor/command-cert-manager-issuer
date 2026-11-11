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
	"golang.org/x/oauth2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

// --- ClientCache key ---------------------------------------------------------------------------

// These hashes were computed before ServiceAccountRef existed. A config without a ref must keep
// hashing to the same value, so an upgrade does not orphan or mis-share cached clients.
func TestConfigHash_NilServiceAccountRefIsUnchanged(t *testing.T) {
	tests := map[string]struct {
		config   *Config
		expected string
	}{
		"basic": {
			config:   &Config{Hostname: "https://command.example.com", APIPath: "api/v1", CaCertsBytes: []byte("ca"), BasicAuth: &BasicAuth{Username: "u", Password: "p"}, AmbientCredentialScopes: []string{""}},
			expected: "0b6ceaf2b722cedc74c61fcef1180b5176d03cfa073340db1ebea8cad50475c0",
		},
		"ambient": {
			config:   &Config{Hostname: "https://command.example.com", APIPath: "api/v1", AmbientCredentialAudience: "aud", AmbientCredentialScopes: []string{"api://x/.default", "s2"}},
			expected: "1dc3c586cce5cd3f81627a6d7282edf581db040e193110dd048802fad7f1f51d",
		},
		"oauth": {
			config:   &Config{Hostname: "h", APIPath: "p", OAuth: &OAuth{TokenURL: "t", ClientID: "c", ClientSecret: "s", Audience: "a", Scopes: []string{"x", "y"}}},
			expected: "792e3f843aa72a8fb428af9e990adfdd28eaf07c649958dd6b454579ba303ac2",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.expected, configHash(tc.config))
		})
	}
}

func TestConfigHash_ServiceAccountRef(t *testing.T) {
	base := func(ref *ServiceAccountRef) *Config {
		return &Config{Hostname: "https://command.example.com", APIPath: "api/v1", AmbientCredentialScopes: []string{"scope"}, ServiceAccountRef: ref}
	}
	ref := func(mutate func(*ServiceAccountRef)) *ServiceAccountRef {
		r := &ServiceAccountRef{Name: "sa", Namespace: "tenant-a", Provider: ProviderAzure, Azure: &AzureIdentity{ClientID: "client", TenantID: "tenant"}}
		if mutate != nil {
			mutate(r)
		}
		return r
	}

	reference := configHash(base(ref(nil)))

	t.Run("a-ref-changes-the-hash", func(t *testing.T) {
		assert.NotEqual(t, configHash(base(nil)), reference)
	})

	t.Run("identical-refs-share-a-hash", func(t *testing.T) {
		assert.Equal(t, reference, configHash(base(ref(nil))))
	})

	differing := map[string]func(*ServiceAccountRef){
		"name":          func(r *ServiceAccountRef) { r.Name = "other" },
		"namespace":     func(r *ServiceAccountRef) { r.Namespace = "tenant-b" },
		"provider":      func(r *ServiceAccountRef) { r.Provider = "" },
		"azure-client":  func(r *ServiceAccountRef) { r.Azure.ClientID = "other" },
		"azure-tenant":  func(r *ServiceAccountRef) { r.Azure.TenantID = "other" },
		"azure-removed": func(r *ServiceAccountRef) { r.Azure = nil },
		"gcp-email": func(r *ServiceAccountRef) {
			r.Azure = nil
			r.GCP = &GCPIdentity{ServiceAccountEmail: "a@example.iam.gserviceaccount.com"}
		},
	}
	for name, mutate := range differing {
		t.Run("different-"+name, func(t *testing.T) {
			assert.NotEqual(t, reference, configHash(base(ref(mutate))))
		})
	}

	t.Run("gcp-emails-differ", func(t *testing.T) {
		a := ref(func(r *ServiceAccountRef) {
			r.Provider, r.Azure, r.GCP = ProviderGCP, nil, &GCPIdentity{ServiceAccountEmail: "a@example.iam.gserviceaccount.com"}
		})
		b := ref(func(r *ServiceAccountRef) {
			r.Provider, r.Azure, r.GCP = ProviderGCP, nil, &GCPIdentity{ServiceAccountEmail: "b@example.iam.gserviceaccount.com"}
		})
		assert.NotEqual(t, configHash(base(a)), configHash(base(b)))
	})

	// Without separators, ("ab","c") and ("a","bc") would hash identically and two tenants
	// could end up sharing one client, and therefore one cloud identity.
	t.Run("adjacent-fields-cannot-run-together", func(t *testing.T) {
		pairs := []struct{ a, b *ServiceAccountRef }{
			{ref(func(r *ServiceAccountRef) { r.Namespace, r.Name = "ab", "c" }), ref(func(r *ServiceAccountRef) { r.Namespace, r.Name = "a", "bc" })},
			{ref(func(r *ServiceAccountRef) { r.Azure.ClientID, r.Azure.TenantID = "ab", "c" }), ref(func(r *ServiceAccountRef) { r.Azure.ClientID, r.Azure.TenantID = "a", "bc" })},
			{ref(func(r *ServiceAccountRef) { r.Name, r.Provider = "sazure", "" }), ref(func(r *ServiceAccountRef) { r.Name, r.Provider = "s", "azure" })},
		}
		for _, p := range pairs {
			assert.NotEqual(t, configHash(base(p.a)), configHash(base(p.b)))
		}
	})

	t.Run("dependencies-are-not-part-of-the-key", func(t *testing.T) {
		withDeps := base(ref(nil))
		withDeps.WorkloadIdentity = &WorkloadIdentityDeps{Requester: &fakeTokenRequester{}, Getter: &fakeAnnotationGetter{}, DefaultAzureTenantID: "x"}
		assert.Equal(t, reference, configHash(withDeps))
	})
}

// --- Config validation -------------------------------------------------------------------------

func TestConfigValidate_ServiceAccountRefIsExclusiveWithDirectCredentials(t *testing.T) {
	ref := &ServiceAccountRef{Name: "sa", Namespace: "ns"}
	valid := func() *Config { return &Config{Hostname: "h", APIPath: "p", ServiceAccountRef: ref} }

	require.NoError(t, valid().validate())

	withBasic := valid()
	withBasic.BasicAuth = &BasicAuth{Username: "u", Password: "p"}
	assert.ErrorIs(t, withBasic.validate(), errInvalidConfig)

	withOAuth := valid()
	withOAuth.OAuth = &OAuth{TokenURL: "t", ClientID: "c", ClientSecret: "s"}
	assert.ErrorIs(t, withOAuth.validate(), errInvalidConfig)
}

// --- newServerConfig ambient branch ------------------------------------------------------------

type staticTokenSource struct{ token string }

func (s staticTokenSource) Token() (*oauth2.Token, error) {
	return &oauth2.Token{AccessToken: s.token, Expiry: time.Now().Add(time.Hour)}, nil
}

type tokenSourceSpies struct {
	defaultAzureCalls int
	defaultGCPCalls   int
	workloadCalls     int
	workloadRef       *ServiceAccountRef
	workloadIdentity  *AzureIdentity
	workloadScopes    []string
	workloadRequester TokenRequester
}

// installSpies replaces the three token source constructors. By default the default-credential
// constructors fail the test if they are called.
func installSpies(t *testing.T, defaultAzure func() (oauth2.TokenSource, error), defaultGCP func() (oauth2.TokenSource, error), workloadErr error) *tokenSourceSpies {
	t.Helper()
	spies := &tokenSourceSpies{}

	originalAzure, originalGCP, originalWorkload := newDefaultAzureTokenSource, newDefaultGCPTokenSource, newWorkloadIdentityAzureToken
	t.Cleanup(func() {
		newDefaultAzureTokenSource, newDefaultGCPTokenSource, newWorkloadIdentityAzureToken = originalAzure, originalGCP, originalWorkload
	})

	newDefaultAzureTokenSource = func(context.Context, []string) (oauth2.TokenSource, error) {
		spies.defaultAzureCalls++
		if defaultAzure == nil {
			return nil, errors.New("default Azure credentials must not be used")
		}
		return defaultAzure()
	}
	newDefaultGCPTokenSource = func(context.Context, string, []string) (oauth2.TokenSource, error) {
		spies.defaultGCPCalls++
		if defaultGCP == nil {
			return nil, errors.New("default GCP credentials must not be used")
		}
		return defaultGCP()
	}
	newWorkloadIdentityAzureToken = func(_ context.Context, ref *ServiceAccountRef, identity *AzureIdentity, requester TokenRequester, scopes []string) (oauth2.TokenSource, error) {
		spies.workloadCalls++
		spies.workloadRef, spies.workloadIdentity, spies.workloadRequester, spies.workloadScopes = ref, identity, requester, scopes
		if workloadErr != nil {
			return nil, workloadErr
		}
		return staticTokenSource{token: "workload"}, nil
	}
	return spies
}

func TestNewServerConfig_ServiceAccountRef(t *testing.T) {
	azureAnnotated := map[string]string{AzureClientIDAnnotation: "ann-client", AzureTenantIDAnnotation: "ann-tenant"}

	newConfig := func(ref *ServiceAccountRef, getter ServiceAccountAnnotationGetter, requester TokenRequester) *Config {
		return &Config{
			Hostname: "command.example.com", APIPath: "api",
			AmbientCredentialScopes: []string{"api://command/.default"},
			ServiceAccountRef:       ref,
			WorkloadIdentity:        &WorkloadIdentityDeps{Getter: getter, Requester: requester, DefaultAzureTenantID: "default-tenant"},
		}
	}
	ref := &ServiceAccountRef{Name: "sa", Namespace: "tenant-a"}

	t.Run("resolves-the-referenced-identity-and-never-touches-default-credentials", func(t *testing.T) {
		spies := installSpies(t, nil, nil, nil)
		requester := &fakeTokenRequester{token: "t"}

		server, err := newServerConfig(context.Background(), newConfig(ref, &fakeAnnotationGetter{annotations: azureAnnotated}, requester))

		require.NoError(t, err)
		require.NotNil(t, server)
		assert.Equal(t, 1, spies.workloadCalls)
		assert.Equal(t, ref, spies.workloadRef)
		assert.Equal(t, &AzureIdentity{ClientID: "ann-client", TenantID: "ann-tenant"}, spies.workloadIdentity)
		assert.Equal(t, []string{"api://command/.default"}, spies.workloadScopes)
		assert.Same(t, requester, spies.workloadRequester)
		assert.Zero(t, spies.defaultAzureCalls, "the operator's own Azure identity must not be used")
		assert.Zero(t, spies.defaultGCPCalls, "the operator's own GCP identity must not be used")
	})

	t.Run("uses-the-controller-default-tenant", func(t *testing.T) {
		spies := installSpies(t, nil, nil, nil)
		getter := &fakeAnnotationGetter{annotations: map[string]string{AzureClientIDAnnotation: "ann-client"}}

		_, err := newServerConfig(context.Background(), newConfig(ref, getter, &fakeTokenRequester{}))

		require.NoError(t, err)
		assert.Equal(t, &AzureIdentity{ClientID: "ann-client", TenantID: "default-tenant"}, spies.workloadIdentity)
	})

	failures := map[string]struct {
		getter ServiceAccountAnnotationGetter
	}{
		"unresolvable-provider": {getter: &fakeAnnotationGetter{annotations: map[string]string{}}},
		"ambiguous-provider":    {getter: &fakeAnnotationGetter{annotations: map[string]string{AzureClientIDAnnotation: "c", GCPServiceAccountAnnotation: "e@x.iam.gserviceaccount.com"}}},
		"lookup-failure":        {getter: &fakeAnnotationGetter{err: errors.New("forbidden")}},
	}
	for name, tc := range failures {
		t.Run(name+"-fails-without-falling-back", func(t *testing.T) {
			// The default constructors would succeed here, so a fall-through would be visible as a nil error.
			spies := installSpies(t,
				func() (oauth2.TokenSource, error) { return staticTokenSource{token: "operator-azure"}, nil },
				func() (oauth2.TokenSource, error) { return staticTokenSource{token: "operator-gcp"}, nil },
				nil)

			server, err := newServerConfig(context.Background(), newConfig(ref, tc.getter, &fakeTokenRequester{}))

			require.Error(t, err)
			assert.ErrorIs(t, err, errAmbientCredentialCreationFailure)
			assert.Nil(t, server)
			assert.Zero(t, spies.defaultAzureCalls)
			assert.Zero(t, spies.defaultGCPCalls)
			assert.Zero(t, spies.workloadCalls)
		})
	}

	t.Run("token-source-failure-does-not-fall-back", func(t *testing.T) {
		boom := errors.New("AADSTS70021")
		spies := installSpies(t,
			func() (oauth2.TokenSource, error) { return staticTokenSource{token: "operator-azure"}, nil },
			func() (oauth2.TokenSource, error) { return staticTokenSource{token: "operator-gcp"}, nil },
			boom)

		server, err := newServerConfig(context.Background(), newConfig(ref, &fakeAnnotationGetter{annotations: azureAnnotated}, &fakeTokenRequester{}))

		require.Error(t, err)
		assert.ErrorIs(t, err, boom)
		assert.Nil(t, server)
		assert.Equal(t, 1, spies.workloadCalls)
		assert.Zero(t, spies.defaultAzureCalls)
		assert.Zero(t, spies.defaultGCPCalls)
	})

	t.Run("gcp-is-not-yet-supported-and-does-not-fall-back", func(t *testing.T) {
		spies := installSpies(t,
			func() (oauth2.TokenSource, error) { return staticTokenSource{token: "operator-azure"}, nil },
			func() (oauth2.TokenSource, error) { return staticTokenSource{token: "operator-gcp"}, nil },
			nil)
		getter := &fakeAnnotationGetter{annotations: map[string]string{GCPServiceAccountAnnotation: "e@x.iam.gserviceaccount.com"}}

		server, err := newServerConfig(context.Background(), newConfig(ref, getter, &fakeTokenRequester{}))

		require.Error(t, err)
		assert.ErrorIs(t, err, errAmbientCredentialCreationFailure)
		assert.Contains(t, err.Error(), "GCP")
		assert.Nil(t, server)
		assert.Zero(t, spies.workloadCalls)
		assert.Zero(t, spies.defaultAzureCalls)
		assert.Zero(t, spies.defaultGCPCalls)
	})

	t.Run("missing-dependencies-is-an-error", func(t *testing.T) {
		spies := installSpies(t, nil, nil, nil)
		for name, deps := range map[string]*WorkloadIdentityDeps{
			"nil-deps":     nil,
			"no-requester": {Getter: &fakeAnnotationGetter{}},
			"no-getter":    {Requester: &fakeTokenRequester{}},
			"both-missing": {},
		} {
			config := newConfig(ref, nil, nil)
			config.WorkloadIdentity = deps

			server, err := newServerConfig(context.Background(), config)

			require.Error(t, err, name)
			assert.ErrorIs(t, err, errInvalidConfig, name)
			assert.Nil(t, server, name)
		}
		assert.Zero(t, spies.defaultAzureCalls)
		assert.Zero(t, spies.defaultGCPCalls)
	})
}

// A config without a ref keeps the existing behavior: DefaultAzureCredential first, then GCP.
func TestNewServerConfig_NilServiceAccountRefKeepsDefaultOrder(t *testing.T) {
	config := func() *Config {
		return &Config{Hostname: "command.example.com", APIPath: "api", AmbientCredentialScopes: []string{"s"}}
	}

	t.Run("azure-first", func(t *testing.T) {
		spies := installSpies(t, func() (oauth2.TokenSource, error) { return staticTokenSource{token: "azure"}, nil }, nil, nil)

		_, err := newServerConfig(context.Background(), config())

		require.NoError(t, err)
		assert.Equal(t, 1, spies.defaultAzureCalls)
		assert.Zero(t, spies.defaultGCPCalls)
		assert.Zero(t, spies.workloadCalls)
	})

	t.Run("falls-back-to-gcp-when-azure-fails", func(t *testing.T) {
		spies := installSpies(t, func() (oauth2.TokenSource, error) { return nil, errors.New("no azure") },
			func() (oauth2.TokenSource, error) { return staticTokenSource{token: "gcp"}, nil }, nil)

		_, err := newServerConfig(context.Background(), config())

		require.NoError(t, err)
		assert.Equal(t, 1, spies.defaultAzureCalls)
		assert.Equal(t, 1, spies.defaultGCPCalls)
		assert.Zero(t, spies.workloadCalls)
	})

	t.Run("both-failing-reports-both-errors", func(t *testing.T) {
		installSpies(t, func() (oauth2.TokenSource, error) { return nil, errors.New("no azure") },
			func() (oauth2.TokenSource, error) { return nil, errors.New("no gcp") }, nil)

		_, err := newServerConfig(context.Background(), config())

		require.Error(t, err)
		assert.ErrorIs(t, err, errAmbientCredentialCreationFailure)
		assert.Contains(t, err.Error(), "no azure")
		assert.Contains(t, err.Error(), "no gcp")
	})
}

// --- ServiceAccount annotation getter ----------------------------------------------------------

func TestServiceAccountAnnotationGetter(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	reader := fake.NewClientBuilder().WithScheme(scheme).WithObjects(
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "tenant-a", Annotations: map[string]string{AzureClientIDAnnotation: "client"}}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "tenant-b", Annotations: map[string]string{AzureClientIDAnnotation: "other"}}},
		&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "bare", Namespace: "tenant-a"}},
	).Build()
	getter := NewServiceAccountAnnotationGetter(reader)

	t.Run("reads-the-named-serviceaccount-in-the-given-namespace-only", func(t *testing.T) {
		a, err := getter.GetServiceAccountAnnotations(context.Background(), "tenant-a", "sa")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{AzureClientIDAnnotation: "client"}, a)

		b, err := getter.GetServiceAccountAnnotations(context.Background(), "tenant-b", "sa")
		require.NoError(t, err)
		assert.Equal(t, map[string]string{AzureClientIDAnnotation: "other"}, b)
	})

	t.Run("no-annotations-is-not-an-error", func(t *testing.T) {
		a, err := getter.GetServiceAccountAnnotations(context.Background(), "tenant-a", "bare")
		require.NoError(t, err)
		assert.Empty(t, a)
	})

	t.Run("missing-serviceaccount-is-an-error", func(t *testing.T) {
		a, err := getter.GetServiceAccountAnnotations(context.Background(), "tenant-a", "missing")
		require.Error(t, err)
		assert.Nil(t, a)
	})

	t.Run("a-serviceaccount-in-another-namespace-is-not-found", func(t *testing.T) {
		_, err := getter.GetServiceAccountAnnotations(context.Background(), "tenant-c", "sa")
		require.Error(t, err)
	})
}
