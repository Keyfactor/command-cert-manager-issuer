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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeAnnotationGetter struct {
	annotations map[string]string
	err         error
	calls       int
	lastNS      string
	lastName    string
}

func (f *fakeAnnotationGetter) GetServiceAccountAnnotations(_ context.Context, namespace, name string) (map[string]string, error) {
	f.calls++
	f.lastNS, f.lastName = namespace, name
	return f.annotations, f.err
}

func TestResolveServiceAccountIdentity(t *testing.T) {
	const defaultTenant = "default-tenant"

	azureAnnotations := map[string]string{
		AzureClientIDAnnotation: "ann-client",
		AzureTenantIDAnnotation: "ann-tenant",
	}
	gcpAnnotations := map[string]string{
		GCPServiceAccountAnnotation: "ann@example.iam.gserviceaccount.com",
	}
	bothAnnotations := map[string]string{
		AzureClientIDAnnotation:     "ann-client",
		AzureTenantIDAnnotation:     "ann-tenant",
		GCPServiceAccountAnnotation: "ann@example.iam.gserviceaccount.com",
	}

	ref := func(mutate func(*ServiceAccountRef)) *ServiceAccountRef {
		r := &ServiceAccountRef{Name: "sa", Namespace: "tenant-a"}
		if mutate != nil {
			mutate(r)
		}
		return r
	}

	type testCase struct {
		name        string
		ref         *ServiceAccountRef
		annotations map[string]string
		getterErr   error
		defaultTen  string

		expectedErr       error
		expectedErrSubstr string
		expectedGetCalls  int
		expectedProvider  string
		expectedAzure     *AzureIdentity
		expectedGCP       *GCPIdentity
		expectedWarning   string // substring; empty means no warnings expected
	}

	lookupErr := errors.New("serviceaccounts \"sa\" is forbidden")

	tests := []testCase{
		// --- annotation inference ---
		{
			name:             "azure-annotations-only",
			ref:              ref(nil),
			annotations:      azureAnnotations,
			expectedGetCalls: 1,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "ann-client", TenantID: "ann-tenant"},
		},
		{
			name:             "gcp-annotation-only",
			ref:              ref(nil),
			annotations:      gcpAnnotations,
			expectedGetCalls: 1,
			expectedProvider: ProviderGCP,
			expectedGCP:      &GCPIdentity{ServiceAccountEmail: "ann@example.iam.gserviceaccount.com"},
		},
		{
			name:              "both-annotations-no-provider-is-ambiguous",
			ref:               ref(nil),
			annotations:       bothAnnotations,
			expectedGetCalls:  1,
			expectedErr:       errAmbiguousProvider,
			expectedErrSubstr: "tenant-a/sa",
		},
		{
			name:              "no-annotations-no-config",
			ref:               ref(nil),
			annotations:       map[string]string{"unrelated": "x"},
			expectedGetCalls:  1,
			expectedErr:       errNoProviderResolved,
			expectedErrSubstr: "tenant-a/sa",
		},
		{
			// An empty annotation value carries no identity and must not select a provider.
			name:             "empty-annotation-values-treated-as-absent",
			ref:              ref(nil),
			annotations:      map[string]string{AzureClientIDAnnotation: "", GCPServiceAccountAnnotation: ""},
			expectedGetCalls: 1,
			expectedErr:      errNoProviderResolved,
		},
		{
			// An empty azure annotation does not make a GCP-annotated SA ambiguous.
			name:             "empty-azure-annotation-does-not-cause-ambiguity",
			ref:              ref(nil),
			annotations:      map[string]string{AzureClientIDAnnotation: "", GCPServiceAccountAnnotation: "ann@example.iam.gserviceaccount.com"},
			expectedGetCalls: 1,
			expectedProvider: ProviderGCP,
			expectedGCP:      &GCPIdentity{ServiceAccountEmail: "ann@example.iam.gserviceaccount.com"},
		},
		{
			// The tenant annotation alone is not enough to infer Azure.
			name:             "tenant-annotation-alone-does-not-infer-provider",
			ref:              ref(nil),
			annotations:      map[string]string{AzureTenantIDAnnotation: "ann-tenant"},
			expectedGetCalls: 1,
			expectedErr:      errNoProviderResolved,
		},

		// --- explicit provider wins over annotations ---
		{
			name:             "explicit-azure-wins-over-both-annotations",
			ref:              ref(func(r *ServiceAccountRef) { r.Provider = ProviderAzure }),
			annotations:      bothAnnotations,
			expectedGetCalls: 1,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "ann-client", TenantID: "ann-tenant"},
			expectedWarning:  GCPServiceAccountAnnotation,
		},
		{
			name:             "explicit-gcp-wins-over-both-annotations",
			ref:              ref(func(r *ServiceAccountRef) { r.Provider = ProviderGCP }),
			annotations:      bothAnnotations,
			expectedGetCalls: 1,
			expectedProvider: ProviderGCP,
			expectedGCP:      &GCPIdentity{ServiceAccountEmail: "ann@example.iam.gserviceaccount.com"},
			expectedWarning:  AzureClientIDAnnotation,
		},
		{
			// An explicit provider is never swapped for the one the annotations point to.
			name:              "explicit-azure-never-falls-through-to-gcp-annotation",
			ref:               ref(func(r *ServiceAccountRef) { r.Provider = ProviderAzure }),
			annotations:       gcpAnnotations,
			expectedGetCalls:  1,
			expectedErr:       errMissingIdentity,
			expectedErrSubstr: "azure clientId",
		},
		{
			name:              "explicit-gcp-never-falls-through-to-azure-annotation",
			ref:               ref(func(r *ServiceAccountRef) { r.Provider = ProviderGCP }),
			annotations:       azureAnnotations,
			expectedGetCalls:  1,
			expectedErr:       errMissingIdentity,
			expectedErrSubstr: "gcp serviceAccountEmail",
		},
		{
			name:              "explicit-provider-no-block-no-annotations",
			ref:               ref(func(r *ServiceAccountRef) { r.Provider = ProviderGCP }),
			annotations:       map[string]string{},
			expectedGetCalls:  1,
			expectedErr:       errMissingIdentity,
			expectedErrSubstr: "tenant-a/sa",
		},

		// --- complete explicit values: the ServiceAccount is not read ---
		{
			name: "explicit-azure-complete-does-not-read-serviceaccount",
			ref: ref(func(r *ServiceAccountRef) {
				r.Provider = ProviderAzure
				r.Azure = &AzureIdentity{ClientID: "cid", TenantID: "tid"}
			}),
			expectedGetCalls: 0,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "cid", TenantID: "tid"},
		},
		{
			name: "explicit-gcp-complete-does-not-read-serviceaccount",
			ref: ref(func(r *ServiceAccountRef) {
				r.Provider = ProviderGCP
				r.GCP = &GCPIdentity{ServiceAccountEmail: "me@example.iam.gserviceaccount.com"}
			}),
			expectedGetCalls: 0,
			expectedProvider: ProviderGCP,
			expectedGCP:      &GCPIdentity{ServiceAccountEmail: "me@example.iam.gserviceaccount.com"},
		},
		{
			// With the identity fully explicit, even a failing lookup must not matter.
			name: "explicit-complete-ignores-lookup-failure",
			ref: ref(func(r *ServiceAccountRef) {
				r.Provider = ProviderAzure
				r.Azure = &AzureIdentity{ClientID: "cid", TenantID: "tid"}
			}),
			getterErr:        lookupErr,
			expectedGetCalls: 0,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "cid", TenantID: "tid"},
		},
		{
			name: "explicit-azure-complete-overrides-all-annotations",
			ref: ref(func(r *ServiceAccountRef) {
				r.Azure = &AzureIdentity{ClientID: "cid", TenantID: "tid"}
			}),
			annotations:      bothAnnotations,
			expectedGetCalls: 0,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "cid", TenantID: "tid"},
		},
		{
			// The provider is inferred from the block when none is set.
			name: "provider-inferred-from-azure-block",
			ref: ref(func(r *ServiceAccountRef) {
				r.Azure = &AzureIdentity{ClientID: "cid", TenantID: "tid"}
			}),
			expectedGetCalls: 0,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "cid", TenantID: "tid"},
		},
		{
			name: "provider-inferred-from-gcp-block",
			ref: ref(func(r *ServiceAccountRef) {
				r.GCP = &GCPIdentity{ServiceAccountEmail: "me@example.iam.gserviceaccount.com"}
			}),
			expectedGetCalls: 0,
			expectedProvider: ProviderGCP,
			expectedGCP:      &GCPIdentity{ServiceAccountEmail: "me@example.iam.gserviceaccount.com"},
		},

		// --- individual fields override the matching annotation ---
		{
			name: "explicit-client-id-overrides-annotation-tenant-from-annotation",
			ref: ref(func(r *ServiceAccountRef) {
				r.Azure = &AzureIdentity{ClientID: "explicit-client"}
			}),
			annotations:      azureAnnotations,
			expectedGetCalls: 1,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "explicit-client", TenantID: "ann-tenant"},
		},
		{
			name: "explicit-tenant-overrides-annotation-client-from-annotation",
			ref: ref(func(r *ServiceAccountRef) {
				r.Azure = &AzureIdentity{TenantID: "explicit-tenant"}
			}),
			annotations:      azureAnnotations,
			defaultTen:       defaultTenant,
			expectedGetCalls: 1,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "ann-client", TenantID: "explicit-tenant"},
		},
		{
			name: "explicit-gcp-email-overrides-annotation",
			ref: ref(func(r *ServiceAccountRef) {
				r.Provider = ProviderGCP
				r.GCP = &GCPIdentity{ServiceAccountEmail: "explicit@example.iam.gserviceaccount.com"}
			}),
			annotations:      gcpAnnotations,
			expectedGetCalls: 0,
			expectedProvider: ProviderGCP,
			expectedGCP:      &GCPIdentity{ServiceAccountEmail: "explicit@example.iam.gserviceaccount.com"},
		},

		// --- tenant fallback chain: explicit -> annotation -> controller default ---
		{
			name:             "tenant-defaults-when-not-annotated",
			ref:              ref(nil),
			annotations:      map[string]string{AzureClientIDAnnotation: "ann-client"},
			defaultTen:       defaultTenant,
			expectedGetCalls: 1,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "ann-client", TenantID: defaultTenant},
		},
		{
			name:             "annotation-tenant-beats-default",
			ref:              ref(nil),
			annotations:      azureAnnotations,
			defaultTen:       defaultTenant,
			expectedGetCalls: 1,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "ann-client", TenantID: "ann-tenant"},
		},
		{
			name: "explicit-tenant-beats-default-and-annotation",
			ref: ref(func(r *ServiceAccountRef) {
				r.Azure = &AzureIdentity{ClientID: "cid", TenantID: "explicit-tenant"}
			}),
			annotations:      azureAnnotations,
			defaultTen:       defaultTenant,
			expectedGetCalls: 0,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "cid", TenantID: "explicit-tenant"},
		},
		{
			name:              "no-tenant-anywhere-is-an-error",
			ref:               ref(nil),
			annotations:       map[string]string{AzureClientIDAnnotation: "ann-client"},
			expectedGetCalls:  1,
			expectedErr:       errMissingIdentity,
			expectedErrSubstr: "azure tenantId",
		},
		{
			name: "explicit-client-without-tenant-checks-annotation-before-default",
			ref: ref(func(r *ServiceAccountRef) {
				r.Azure = &AzureIdentity{ClientID: "cid"}
			}),
			annotations:      map[string]string{AzureTenantIDAnnotation: "ann-tenant"},
			defaultTen:       defaultTenant,
			expectedGetCalls: 1,
			expectedProvider: ProviderAzure,
			expectedAzure:    &AzureIdentity{ClientID: "cid", TenantID: "ann-tenant"},
		},
		{
			// The default tenant is Azure-only and must never leak into the GCP result.
			name:             "default-tenant-ignored-for-gcp",
			ref:              ref(nil),
			annotations:      gcpAnnotations,
			defaultTen:       defaultTenant,
			expectedGetCalls: 1,
			expectedProvider: ProviderGCP,
			expectedGCP:      &GCPIdentity{ServiceAccountEmail: "ann@example.iam.gserviceaccount.com"},
		},

		// --- lookup failures ---
		{
			name:              "lookup-error-is-surfaced-and-wrapped",
			ref:               ref(nil),
			getterErr:         lookupErr,
			expectedGetCalls:  1,
			expectedErr:       errServiceAccountLookup,
			expectedErrSubstr: "tenant-a/sa",
		},
		{
			name:             "lookup-error-surfaced-when-explicit-values-incomplete",
			ref:              ref(func(r *ServiceAccountRef) { r.Provider = ProviderAzure; r.Azure = &AzureIdentity{ClientID: "cid"} }),
			defaultTen:       defaultTenant,
			getterErr:        lookupErr,
			expectedGetCalls: 1,
			expectedErr:      errServiceAccountLookup,
		},

		// --- defensive validation, in case the CRD and controller checks are bypassed ---
		{
			name:        "nil-ref",
			ref:         nil,
			expectedErr: errMissingServiceAccountRef,
		},
		{
			name:        "empty-name",
			ref:         ref(func(r *ServiceAccountRef) { r.Name = "" }),
			expectedErr: errInvalidIdentityConfig,
		},
		{
			// An unresolved namespace must never turn into a lookup in the empty namespace.
			name:        "empty-namespace",
			ref:         ref(func(r *ServiceAccountRef) { r.Namespace = "" }),
			expectedErr: errInvalidIdentityConfig,
		},
		{
			name:        "unknown-provider",
			ref:         ref(func(r *ServiceAccountRef) { r.Provider = "aws" }),
			expectedErr: errInvalidIdentityConfig,
		},
		{
			name: "provider-azure-with-gcp-block",
			ref: ref(func(r *ServiceAccountRef) {
				r.Provider = ProviderAzure
				r.GCP = &GCPIdentity{ServiceAccountEmail: "x@example.iam.gserviceaccount.com"}
			}),
			annotations: azureAnnotations,
			expectedErr: errInvalidIdentityConfig,
		},
		{
			name: "provider-gcp-with-azure-block",
			ref: ref(func(r *ServiceAccountRef) {
				r.Provider = ProviderGCP
				r.Azure = &AzureIdentity{ClientID: "cid", TenantID: "tid"}
			}),
			annotations: gcpAnnotations,
			expectedErr: errInvalidIdentityConfig,
		},
		{
			name: "both-blocks-no-provider",
			ref: ref(func(r *ServiceAccountRef) {
				r.Azure = &AzureIdentity{ClientID: "cid", TenantID: "tid"}
				r.GCP = &GCPIdentity{ServiceAccountEmail: "x@example.iam.gserviceaccount.com"}
			}),
			expectedErr: errInvalidIdentityConfig,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			getter := &fakeAnnotationGetter{annotations: tc.annotations, err: tc.getterErr}

			identity, err := ResolveServiceAccountIdentity(context.Background(), tc.ref, getter, tc.defaultTen)

			assert.Equal(t, tc.expectedGetCalls, getter.calls, "unexpected number of ServiceAccount reads")
			if getter.calls > 0 {
				assert.Equal(t, "tenant-a", getter.lastNS)
				assert.Equal(t, "sa", getter.lastName)
			}

			if tc.expectedErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedErr)
				if tc.expectedErrSubstr != "" {
					assert.Contains(t, err.Error(), tc.expectedErrSubstr)
				}
				if tc.getterErr != nil && tc.expectedErr == errServiceAccountLookup {
					assert.ErrorIs(t, err, tc.getterErr, "the underlying lookup error must stay reachable")
				}
				assert.Nil(t, identity, "a failed resolution must not return an identity")
				return
			}

			require.NoError(t, err)
			require.NotNil(t, identity)
			assert.Equal(t, tc.expectedProvider, identity.Provider)
			assert.Equal(t, tc.expectedAzure, identity.Azure)
			assert.Equal(t, tc.expectedGCP, identity.GCP)
			if tc.expectedWarning == "" {
				assert.Empty(t, identity.Warnings)
			} else {
				require.Len(t, identity.Warnings, 1)
				assert.Contains(t, identity.Warnings[0], tc.expectedWarning)
			}
		})
	}
}
