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
	"errors"
	"testing"

	commandissuer "github.com/Keyfactor/command-cert-manager-issuer/api/v1alpha1"
	commandissuerv1alpha1 "github.com/Keyfactor/command-cert-manager-issuer/api/v1alpha1"
	"github.com/Keyfactor/command-cert-manager-issuer/internal/command"
	logrtesting "github.com/go-logr/logr/testing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type fakeHealthChecker struct {
	supportsMetadata bool
	errCheck         error
}

func (f *fakeHealthChecker) Check(context.Context) error {
	return f.errCheck
}

func (f *fakeHealthChecker) CommandSupportsMetadata() (bool, error) {
	return f.supportsMetadata, nil
}

var newFakeHealthCheckerBuilder = func(builderErr error, checkerErr error, supportsMetadata bool) func(context.Context, *command.Config) (command.HealthChecker, error) {
	return func(context.Context, *command.Config) (command.HealthChecker, error) {
		return &fakeHealthChecker{
			errCheck: checkerErr,
		}, builderErr
	}
}

func TestIssuerReconcile(t *testing.T) {
	// caCert, rootKey := issueTestCertificate(t, "Root-CA", nil, nil)
	// caCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	// serverCert, _ := issueTestCertificate(t, "Server", caCert, rootKey)
	// serverCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCert.Raw})
	// caChain := append(serverCertPem, caCertPem...)

	type testCase struct {
		kind                                     string
		name                                     types.NamespacedName
		objects                                  []client.Object
		healthCheckerBuilder                     command.HealthCheckerBuilder
		clusterResourceNamespace                 string
		expectedResult                           ctrl.Result
		expectedError                            error
		expectedReadyConditionStatus             commandissuerv1alpha1.ConditionStatus
		expectedMetadataSupportedConditionStatus commandissuerv1alpha1.ConditionStatus
	}

	tests := map[string]testCase{
		"success-issuer-basicauth": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
			},
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, false),
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"issuer-basicauth-no-username": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
		},
		"issuer-basicauth-no-password": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
		},
		"success-clusterissuer-basicauth": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "clusterissuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "clusterissuer1-credentials",
						Namespace: "kube-system",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
			},
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, false),
			clusterResourceNamespace:                 "kube-system",
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"success-issuer-oauth": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						commandissuerv1alpha1.OAuthTokenURLKey:     []byte("https://dev.idp.com/oauth/token"),
						commandissuerv1alpha1.OAuthClientIDKey:     []byte("fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"),
						commandissuerv1alpha1.OAuthClientSecretKey: []byte("1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"),
						commandissuerv1alpha1.OAuthScopesKey:       []byte("read:certificates,write:certificates"),
						commandissuerv1alpha1.OAuthAudienceKey:     []byte("https://command.example.com"),
					},
				},
			},
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, false),
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"issuer-oauth-no-tokenurl": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						commandissuerv1alpha1.OAuthClientIDKey:     []byte("fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"),
						commandissuerv1alpha1.OAuthClientSecretKey: []byte("1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"),
						commandissuerv1alpha1.OAuthScopesKey:       []byte("read:certificates,write:certificates"),
						commandissuerv1alpha1.OAuthAudienceKey:     []byte("https://command.example.com"),
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
		},
		"issuer-oauth-no-clientid": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						commandissuerv1alpha1.OAuthTokenURLKey:     []byte("https://dev.idp.com/oauth/token"),
						commandissuerv1alpha1.OAuthClientSecretKey: []byte("1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"),
						commandissuerv1alpha1.OAuthScopesKey:       []byte("read:certificates,write:certificates"),
						commandissuerv1alpha1.OAuthAudienceKey:     []byte("https://command.example.com"),
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
		},
		"issuer-oauth-no-clientsecret": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						commandissuerv1alpha1.OAuthTokenURLKey: []byte("https://dev.idp.com/oauth/token"),
						commandissuerv1alpha1.OAuthClientIDKey: []byte("fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"),
						commandissuerv1alpha1.OAuthScopesKey:   []byte("read:certificates,write:certificates"),
						commandissuerv1alpha1.OAuthAudienceKey: []byte("https://command.example.com"),
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
		},
		"success-clusterissuer-oauth": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "clusterissuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "clusterissuer1-credentials",
						Namespace: "kube-system",
					},
					Data: map[string][]byte{
						commandissuerv1alpha1.OAuthTokenURLKey:     []byte("https://dev.idp.com/oauth/token"),
						commandissuerv1alpha1.OAuthClientIDKey:     []byte("fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"),
						commandissuerv1alpha1.OAuthClientSecretKey: []byte("1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"),
						commandissuerv1alpha1.OAuthScopesKey:       []byte("read:certificates,write:certificates"),
						commandissuerv1alpha1.OAuthAudienceKey:     []byte("https://command.example.com"),
					},
				},
			},
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, false),
			clusterResourceNamespace:                 "kube-system",
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"issuer-kind-Unrecognized": {
			kind: "UnrecognizedType",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
		},
		"issuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
		},
		"issuer-missing-secret": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
		},
		"issuer-failing-healthchecker-builder": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
			},
			healthCheckerBuilder: newFakeHealthCheckerBuilder(errors.New("simulated health checker builder error"), nil, false),

			expectedError:                            errHealthCheckerBuilder,
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
		},
		"issuer-failing-healthchecker-check": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuerv1alpha1.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuerv1alpha1.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuerv1alpha1.IssuerStatus{
						Conditions: []commandissuerv1alpha1.IssuerCondition{
							{
								Type:   commandissuerv1alpha1.IssuerConditionReady,
								Status: commandissuerv1alpha1.ConditionUnknown,
							},
							{
								Type:   commandissuerv1alpha1.IssuerConditionSupportsMetadata,
								Status: commandissuerv1alpha1.ConditionFalse,
							},
						},
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
			},
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, errors.New("simulated health check error"), false),
			expectedError:                            errHealthCheckerCheck,
			expectedReadyConditionStatus:             commandissuerv1alpha1.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuerv1alpha1.ConditionFalse,
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, commandissuerv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.objects...).
				WithStatusSubresource(tc.objects...).
				Build()
			if tc.kind == "" {
				tc.kind = "Issuer"
			}
			controller := IssuerReconciler{
				Kind:                              tc.kind,
				Client:                            fakeClient,
				Scheme:                            scheme,
				HealthCheckerBuilder:              tc.healthCheckerBuilder,
				ClusterResourceNamespace:          tc.clusterResourceNamespace,
				SecretAccessGrantedAtClusterLevel: true,
			}
			result, err := controller.Reconcile(
				ctrl.LoggerInto(context.TODO(), logrtesting.NewTestLogger(t)),
				reconcile.Request{NamespacedName: tc.name},
			)
			if tc.expectedError != nil {
				assertErrorIs(t, tc.expectedError, err)
			} else {
				assert.NoError(t, err)
			}

			assert.Equal(t, tc.expectedResult, result, "Unexpected result")

			if tc.expectedReadyConditionStatus != "" {
				issuer, err := controller.newIssuer()
				require.NoError(t, err)
				require.NoError(t, fakeClient.Get(context.TODO(), tc.name, issuer))
				require.NoError(t, err)
				assert.True(t, issuer.GetStatus().HasCondition(commandissuerv1alpha1.IssuerConditionReady, tc.expectedReadyConditionStatus))
				assert.True(t, issuer.GetStatus().HasCondition(commandissuerv1alpha1.IssuerConditionSupportsMetadata, tc.expectedMetadataSupportedConditionStatus))
			}
		})
	}
}

func TestCommandConfigFromIssuer(t *testing.T) {
	type testCase struct {
		name             string
		issuerSpec       commandissuerv1alpha1.IssuerSpec
		secretNamespace  string
		secrets          []client.Object
		expectedConfig   *command.Config
		expectedError    error
		expectedErrorMsg string
	}

	tests := []testCase{
		{
			name: "success-basic-auth",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				APIPath:    "/api/v1",
				SecretName: "auth-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
			},
			expectedConfig: &command.Config{
				Hostname: "https://ca.example.com",
				APIPath:  "/api/v1",
				BasicAuth: &command.BasicAuth{
					Username: "username",
					Password: "password",
				},
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "success-basic-auth-with-ca-cert-secret",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:     "https://ca.example.com",
				APIPath:      "/api/v1",
				SecretName:   "auth-secret",
				CaSecretName: "ca-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nABCD...\n-----END CERTIFICATE-----"),
						"ca.crt":  []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"),
					},
				},
			},
			expectedConfig: &command.Config{
				Hostname:     "https://ca.example.com",
				APIPath:      "/api/v1",
				CaCertsBytes: []byte("-----BEGIN CERTIFICATE-----\nABCD...\n-----END CERTIFICATE-----"),
				BasicAuth: &command.BasicAuth{
					Username: "username",
					Password: "password",
				},
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "success-basic-auth-with-ca-cert-secret-with-key",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:     "https://ca.example.com",
				APIPath:      "/api/v1",
				SecretName:   "auth-secret",
				CaSecretName: "ca-secret",
				CaBundleKey:  "ca.crt",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nABCD...\n-----END CERTIFICATE-----"),
						"ca.crt":  []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"),
					},
				},
			},
			expectedConfig: &command.Config{
				Hostname:     "https://ca.example.com",
				APIPath:      "/api/v1",
				CaCertsBytes: []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"),
				BasicAuth: &command.BasicAuth{
					Username: "username",
					Password: "password",
				},
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "success-basic-auth-with-ca-cert-configmap",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:              "https://ca.example.com",
				APIPath:               "/api/v1",
				SecretName:            "auth-secret",
				CaBundleConfigMapName: "ca-configmap",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-configmap",
						Namespace: "ns1",
					},
					Data: map[string]string{
						"ca.crt":  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
						"tls.crt": "-----BEGIN CERTIFICATE-----\nABCD...\n-----END CERTIFICATE-----",
					},
				},
			},
			expectedConfig: &command.Config{
				Hostname:     "https://ca.example.com",
				APIPath:      "/api/v1",
				CaCertsBytes: []byte("-----BEGIN CERTIFICATE-----\nABCD...\n-----END CERTIFICATE-----"),
				BasicAuth: &command.BasicAuth{
					Username: "username",
					Password: "password",
				},
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "success-basic-auth-with-ca-cert-configmap-with-key",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:              "https://ca.example.com",
				APIPath:               "/api/v1",
				SecretName:            "auth-secret",
				CaBundleConfigMapName: "ca-configmap",
				CaBundleKey:           "ca.crt",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-configmap",
						Namespace: "ns1",
					},
					Data: map[string]string{
						"ca.crt":  "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
						"tls.crt": "-----BEGIN CERTIFICATE-----\nABCD...\n-----END CERTIFICATE-----",
					},
				},
			},
			expectedConfig: &command.Config{
				Hostname:     "https://ca.example.com",
				APIPath:      "/api/v1",
				CaCertsBytes: []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"),
				BasicAuth: &command.BasicAuth{
					Username: "username",
					Password: "password",
				},
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "success-basic-auth-with-ca-cert-configmap-overwrites-secret",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:              "https://ca.example.com",
				APIPath:               "/api/v1",
				SecretName:            "auth-secret",
				CaSecretName:          "ca-secret",
				CaBundleConfigMapName: "ca-configmap",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						"ca.crt": []byte("-----BEGIN CERTIFICATE-----\nABCD...\n-----END CERTIFICATE-----"),
					},
				},
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-configmap",
						Namespace: "ns1",
					},
					Data: map[string]string{
						"ca.crt": "-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----",
					},
				},
			},
			expectedConfig: &command.Config{
				Hostname:     "https://ca.example.com",
				APIPath:      "/api/v1",
				CaCertsBytes: []byte("-----BEGIN CERTIFICATE-----\nMIIC...\n-----END CERTIFICATE-----"),
				BasicAuth: &command.BasicAuth{
					Username: "username",
					Password: "password",
				},
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "success-oauth-minimal",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				APIPath:    "/api/v1",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						commandissuer.OAuthTokenURLKey:     []byte("https://oauth.example.com/token"),
						commandissuer.OAuthClientIDKey:     []byte("client-id"),
						commandissuer.OAuthClientSecretKey: []byte("client-secret"),
					},
				},
			},
			expectedConfig: &command.Config{
				Hostname: "https://ca.example.com",
				APIPath:  "/api/v1",
				OAuth: &command.OAuth{
					TokenURL:     "https://oauth.example.com/token",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "success-oauth-with-scopes-and-audience",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				APIPath:    "/api/v1",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						commandissuer.OAuthTokenURLKey:     []byte("https://oauth.example.com/token"),
						commandissuer.OAuthClientIDKey:     []byte("client-id"),
						commandissuer.OAuthClientSecretKey: []byte("client-secret"),
						commandissuer.OAuthScopesKey:       []byte("scope1,scope2,scope3"),
						commandissuer.OAuthAudienceKey:     []byte("https://api.example.com"),
					},
				},
			},
			expectedConfig: &command.Config{
				Hostname: "https://ca.example.com",
				APIPath:  "/api/v1",
				OAuth: &command.OAuth{
					TokenURL:     "https://oauth.example.com/token",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					Scopes:       []string{"scope1", "scope2", "scope3"},
					Audience:     "https://api.example.com",
				},
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "success-ambient-credentials-with-scopes",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname: "https://ca.example.com",
				APIPath:  "/api/v1",
				Scopes:   "scope1,scope2",
				Audience: "https://api.example.com",
			},
			secretNamespace: "ns1",
			secrets:         []client.Object{},
			expectedConfig: &command.Config{
				Hostname:                  "https://ca.example.com",
				APIPath:                   "/api/v1",
				AmbientCredentialScopes:   []string{"scope1", "scope2"},
				AmbientCredentialAudience: "https://api.example.com",
			},
		},
		{
			name: "success-no-auth-secret",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname: "https://ca.example.com",
				APIPath:  "/api/v1",
			},
			secretNamespace: "ns1",
			secrets:         []client.Object{},
			expectedConfig: &command.Config{
				Hostname:                  "https://ca.example.com",
				APIPath:                   "/api/v1",
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "error-auth-secret-not-found",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "missing-secret",
			},
			secretNamespace: "ns1",
			secrets:         []client.Object{},
			expectedError:   errGetAuthSecret,
		},
		{
			name: "error-ca-secret-not-found",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:     "https://ca.example.com",
				CaSecretName: "missing-ca-secret",
			},
			secretNamespace: "ns1",
			secrets:         []client.Object{},
			expectedError:   errGetCaSecret,
		},
		{
			name: "error-ca-secret-key-not-found",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:     "https://ca.example.com",
				CaSecretName: "ca-secret",
				CaBundleKey:  "ca.crt",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						"tls.crt": []byte("-----BEGIN CERTIFICATE-----\nABCD...\n-----END CERTIFICATE-----"),
					},
				},
			},
			expectedError: errGetCaBundleKey,
		},
		{
			name: "error-ca-configmap-not-found",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:              "https://ca.example.com",
				CaBundleConfigMapName: "missing-ca-bundle",
			},
			secretNamespace: "ns1",
			secrets:         []client.Object{},
			expectedError:   errGetCaConfigMap,
		},
		{
			name: "error-ca-configmap-key-not-found",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:              "https://ca.example.com",
				CaBundleConfigMapName: "ca-configmap",
				CaBundleKey:           "ca.crt",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.ConfigMap{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "ca-configmap",
						Namespace: "ns1",
					},
					Data: map[string]string{
						"tls.crt": "-----BEGIN CERTIFICATE-----\nABCD...\n-----END CERTIFICATE-----",
					},
				},
			},
			expectedError: errGetCaBundleKey,
		},
		{
			name: "error-basic-auth-no-username",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "auth-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
			},
			expectedError:    errGetAuthSecret,
			expectedErrorMsg: "found basic auth secret with no username",
		},
		{
			name: "error-basic-auth-no-password",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "auth-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
					},
				},
			},
			expectedError:    errGetAuthSecret,
			expectedErrorMsg: "found basic auth secret with no password",
		},
		{
			name: "error-oauth-no-token-url",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						commandissuer.OAuthClientIDKey:     []byte("client-id"),
						commandissuer.OAuthClientSecretKey: []byte("client-secret"),
					},
				},
			},
			expectedError:    errGetAuthSecret,
			expectedErrorMsg: "found secret with no tokenUrl",
		},
		{
			name: "error-oauth-no-client-id",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						commandissuer.OAuthTokenURLKey:     []byte("https://oauth.example.com/token"),
						commandissuer.OAuthClientSecretKey: []byte("client-secret"),
					},
				},
			},
			expectedError:    errGetAuthSecret,
			expectedErrorMsg: "found secret with no clientId",
		},
		{
			name: "error-oauth-no-client-secret",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeOpaque,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "oauth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						commandissuer.OAuthTokenURLKey: []byte("https://oauth.example.com/token"),
						commandissuer.OAuthClientIDKey: []byte("client-id"),
					},
				},
			},
			expectedError:    errGetAuthSecret,
			expectedErrorMsg: "found secret with no clientSecret",
		},
		{
			name: "error-unsupported-secret-type",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "auth-secret",
			},
			secretNamespace: "ns1",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeTLS,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "ns1",
					},
					Data: map[string][]byte{
						"tls.crt": []byte("cert"),
						"tls.key": []byte("key"),
					},
				},
			},
			expectedError:    errGetAuthSecret,
			expectedErrorMsg: "found secret with unsupported type",
		},
		{
			name: "success-cluster-scoped-secret-namespace",
			issuerSpec: commandissuerv1alpha1.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "auth-secret",
			},
			secretNamespace: "kube-system",
			secrets: []client.Object{
				&corev1.Secret{
					Type: corev1.SecretTypeBasicAuth,
					ObjectMeta: metav1.ObjectMeta{
						Name:      "auth-secret",
						Namespace: "kube-system",
					},
					Data: map[string][]byte{
						corev1.BasicAuthUsernameKey: []byte("username"),
						corev1.BasicAuthPasswordKey: []byte("password"),
					},
				},
			},
			expectedConfig: &command.Config{
				Hostname: "https://ca.example.com",
				BasicAuth: &command.BasicAuth{
					Username: "username",
					Password: "password",
				},
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, commandissuerv1alpha1.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.secrets...).
				Build()

			// Create a minimal issuer with the test spec
			issuer := &commandissuerv1alpha1.Issuer{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-issuer",
					Namespace: tc.secretNamespace,
				},
				Spec: tc.issuerSpec,
			}

			ctx := context.Background()
			config, err := commandConfigFromIssuer(ctx, fakeClient, issuer, tc.secretNamespace)

			if tc.expectedError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.expectedError)
				if tc.expectedErrorMsg != "" {
					assert.Contains(t, err.Error(), tc.expectedErrorMsg)
				}
				assert.Nil(t, config)
			} else {
				require.NoError(t, err)
				require.NotNil(t, config)
				assert.Equal(t, tc.expectedConfig.Hostname, config.Hostname)
				assert.Equal(t, tc.expectedConfig.APIPath, config.APIPath)
				assert.Equal(t, tc.expectedConfig.CaCertsBytes, config.CaCertsBytes)
				assert.Equal(t, tc.expectedConfig.BasicAuth, config.BasicAuth)
				assert.Equal(t, tc.expectedConfig.OAuth, config.OAuth)
				assert.Equal(t, tc.expectedConfig.AmbientCredentialScopes, config.AmbientCredentialScopes)
				assert.Equal(t, tc.expectedConfig.AmbientCredentialAudience, config.AmbientCredentialAudience)
			}
		})
	}
}
