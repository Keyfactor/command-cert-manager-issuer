/*
Copyright © 2024 Keyfactor

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
