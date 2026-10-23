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
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	commandissuer "github.com/Keyfactor/command-cert-manager-issuer/api/v1alpha1"
	"github.com/Keyfactor/command-cert-manager-issuer/internal/command"
	"github.com/go-logr/logr"
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
			supportsMetadata: supportsMetadata,
			errCheck:         checkerErr,
		}, builderErr
	}
}

const defaultHealthcheckInterval = time.Minute * 10

func TestIssuerReconcile(t *testing.T) {
	type testCase struct {
		kind                                     string
		name                                     types.NamespacedName
		objects                                  []client.Object
		healthCheckerBuilder                     command.HealthCheckerBuilder
		clusterResourceNamespace                 string
		defaultHealthCheckInterval               *time.Duration
		expectedResult                           ctrl.Result
		expectedError                            error
		expectedReadyConditionStatus             commandissuer.ConditionStatus
		expectedMetadataSupportedConditionStatus commandissuer.ConditionStatus
	}

	tests := map[string]testCase{
		"success-issuer-basicauth": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
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
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthcheckInterval},
		},
		"issuer-basicauth-no-username": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
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
			expectedReadyConditionStatus:             commandissuer.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
		},
		"issuer-basicauth-no-password": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
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
			expectedReadyConditionStatus:             commandissuer.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
		},
		"success-clusterissuer-basicauth": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "clusterissuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
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
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthcheckInterval},
		},
		"success-issuer-oauth": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
						commandissuer.OAuthTokenURLKey:     []byte("https://dev.idp.com/oauth/token"),
						commandissuer.OAuthClientIDKey:     []byte("fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"),
						commandissuer.OAuthClientSecretKey: []byte("1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"),
						commandissuer.OAuthScopesKey:       []byte("read:certificates,write:certificates"),
						commandissuer.OAuthAudienceKey:     []byte("https://command.example.com"),
					},
				},
			},
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, false),
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthcheckInterval},
		},
		"issuer-oauth-no-tokenurl": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
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
						commandissuer.OAuthClientIDKey:     []byte("fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"),
						commandissuer.OAuthClientSecretKey: []byte("1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"),
						commandissuer.OAuthScopesKey:       []byte("read:certificates,write:certificates"),
						commandissuer.OAuthAudienceKey:     []byte("https://command.example.com"),
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuer.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
		},
		"issuer-oauth-no-clientid": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
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
						commandissuer.OAuthTokenURLKey:     []byte("https://dev.idp.com/oauth/token"),
						commandissuer.OAuthClientSecretKey: []byte("1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"),
						commandissuer.OAuthScopesKey:       []byte("read:certificates,write:certificates"),
						commandissuer.OAuthAudienceKey:     []byte("https://command.example.com"),
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuer.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
		},
		"issuer-oauth-no-clientsecret": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
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
						commandissuer.OAuthTokenURLKey: []byte("https://dev.idp.com/oauth/token"),
						commandissuer.OAuthClientIDKey: []byte("fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"),
						commandissuer.OAuthScopesKey:   []byte("read:certificates,write:certificates"),
						commandissuer.OAuthAudienceKey: []byte("https://command.example.com"),
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuer.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
		},
		"success-clusterissuer-oauth": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "clusterissuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
						commandissuer.OAuthTokenURLKey:     []byte("https://dev.idp.com/oauth/token"),
						commandissuer.OAuthClientIDKey:     []byte("fi3ElQUVoBBHyRNt4mpUxG9WY65AOCcJ"),
						commandissuer.OAuthClientSecretKey: []byte("1EXHdD7Ikmmv0OkBoJZZtzOG5iAzvwdqBVuvquf-QEvL6fLrEG_heJHphtEXVj9H"),
						commandissuer.OAuthScopesKey:       []byte("read:certificates,write:certificates"),
						commandissuer.OAuthAudienceKey:     []byte("https://command.example.com"),
					},
				},
			},
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, false),
			clusterResourceNamespace:                 "kube-system",
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthcheckInterval},
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
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
							},
						},
					},
				},
			},
			expectedError:                            errGetAuthSecret,
			expectedReadyConditionStatus:             commandissuer.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
		},
		"issuer-failing-healthchecker-builder": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
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
			expectedReadyConditionStatus:             commandissuer.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
		},
		"issuer-failing-healthchecker-check": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
							},
							{
								Type:   commandissuer.IssuerConditionSupportsMetadata,
								Status: commandissuer.ConditionFalse,
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
			expectedReadyConditionStatus:             commandissuer.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionFalse,
		},
		"success-custom-healthcheck-interval-issuer": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
						HealthCheck: &commandissuer.HealthCheckConfig{
							Enabled:  true,
							Interval: to.Ptr(metav1.Duration{Duration: 30 * time.Second}),
						},
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, true),
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionTrue,
			expectedResult:                           ctrl.Result{RequeueAfter: time.Duration(30) * time.Second},
		},
		"success-custom-healthcheck-interval-clusterissuer": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "clusterissuer1-credentials",
						HealthCheck: &commandissuer.HealthCheckConfig{
							Enabled:  true,
							Interval: to.Ptr(metav1.Duration{Duration: 120 * time.Second}),
						},
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, true),
			clusterResourceNamespace:                 "kube-system",
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionTrue,
			expectedResult:                           ctrl.Result{RequeueAfter: time.Duration(120) * time.Second},
		},
		"success-healthcheck-disabled": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "clusterissuer1-credentials",
						HealthCheck: &commandissuer.HealthCheckConfig{
							Enabled: false,
						},
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, true),
			clusterResourceNamespace:                 "kube-system",
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionTrue,
			expectedResult:                           ctrl.Result{RequeueAfter: time.Duration(0)},
		},
		"success-no-healthcheck-interval": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "clusterissuer1-credentials",
						HealthCheck: &commandissuer.HealthCheckConfig{
							Enabled:  true,
							Interval: nil,
						},
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, true),
			clusterResourceNamespace:                 "kube-system",
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionTrue,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthcheckInterval},
		},
		"success-nil-healthcheck-interval-defaults": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "clusterissuer1-credentials",
						HealthCheck: &commandissuer.HealthCheckConfig{
							Enabled:  true,
							Interval: nil,
						},
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, true),
			clusterResourceNamespace:                 "kube-system",
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionTrue,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthcheckInterval},
		},
		"success-default-healthcheck-interval": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName:  "clusterissuer1-credentials",
						HealthCheck: nil,
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
			defaultHealthCheckInterval:               to.Ptr(time.Duration(2) * time.Minute),
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, true),
			clusterResourceNamespace:                 "kube-system",
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionTrue,
			expectedResult:                           ctrl.Result{RequeueAfter: time.Duration(2) * time.Minute},
		},
		"success-nil-healthcheck-defaults": {
			kind: "ClusterIssuer",
			name: types.NamespacedName{Name: "clusterissuer1"},
			objects: []client.Object{
				&commandissuer.ClusterIssuer{
					ObjectMeta: metav1.ObjectMeta{
						Name: "clusterissuer1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName:  "clusterissuer1-credentials",
						HealthCheck: nil,
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
			healthCheckerBuilder:                     newFakeHealthCheckerBuilder(nil, nil, true),
			clusterResourceNamespace:                 "kube-system",
			expectedReadyConditionStatus:             commandissuer.ConditionTrue,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionTrue,
			expectedResult:                           ctrl.Result{RequeueAfter: defaultHealthcheckInterval},
		},
		"error-healthcheck-minimum-value": {
			kind: "Issuer",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
					Spec: commandissuer.IssuerSpec{
						SecretName: "issuer1-credentials",
						HealthCheck: &commandissuer.HealthCheckConfig{
							Enabled:  true,
							Interval: to.Ptr(metav1.Duration{Duration: 29 * time.Second}),
						},
					},
					Status: commandissuer.IssuerStatus{
						Conditions: []commandissuer.IssuerCondition{
							{
								Type:   commandissuer.IssuerConditionReady,
								Status: commandissuer.ConditionUnknown,
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
			expectedReadyConditionStatus:             commandissuer.ConditionFalse,
			expectedMetadataSupportedConditionStatus: commandissuer.ConditionUnknown,
			expectedResult:                           ctrl.Result{},
		},
	}

	scheme := runtime.NewScheme()
	require.NoError(t, commandissuer.AddToScheme(scheme))
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

			testCaseHealthcheckInterval := defaultHealthcheckInterval

			if tc.defaultHealthCheckInterval != nil {
				testCaseHealthcheckInterval = *tc.defaultHealthCheckInterval
			}

			controller := IssuerReconciler{
				Kind:                              tc.kind,
				Client:                            fakeClient,
				Scheme:                            scheme,
				HealthCheckerBuilder:              tc.healthCheckerBuilder,
				ClusterResourceNamespace:          tc.clusterResourceNamespace,
				SecretAccessGrantedAtClusterLevel: true,
				DefaultHealthCheckInterval:        testCaseHealthcheckInterval,
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
				assert.True(t, issuer.GetStatus().HasCondition(commandissuer.IssuerConditionReady, tc.expectedReadyConditionStatus))
				assert.True(t, issuer.GetStatus().HasCondition(commandissuer.IssuerConditionSupportsMetadata, tc.expectedMetadataSupportedConditionStatus))
			}
		})
	}
}

func TestCommandConfigFromIssuer(t *testing.T) {
	type testCase struct {
		name             string
		issuerSpec       commandissuer.IssuerSpec
		secretNamespace  string
		objects          []client.Object
		expectedConfig   *command.Config
		expectedError    error
		expectedErrorMsg string
	}

	tests := []testCase{
		{
			name: "success-basic-auth",
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				APIPath:    "/api/v1",
				SecretName: "auth-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:     "https://ca.example.com",
				APIPath:      "/api/v1",
				SecretName:   "auth-secret",
				CaSecretName: "ca-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:     "https://ca.example.com",
				APIPath:      "/api/v1",
				SecretName:   "auth-secret",
				CaSecretName: "ca-secret",
				CaBundleKey:  "ca.crt",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:              "https://ca.example.com",
				APIPath:               "/api/v1",
				SecretName:            "auth-secret",
				CaBundleConfigMapName: "ca-configmap",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:              "https://ca.example.com",
				APIPath:               "/api/v1",
				SecretName:            "auth-secret",
				CaBundleConfigMapName: "ca-configmap",
				CaBundleKey:           "ca.crt",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:              "https://ca.example.com",
				APIPath:               "/api/v1",
				SecretName:            "auth-secret",
				CaSecretName:          "ca-secret",
				CaBundleConfigMapName: "ca-configmap",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				APIPath:    "/api/v1",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				APIPath:    "/api/v1",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname: "https://ca.example.com",
				APIPath:  "/api/v1",
				Scopes:   "scope1,scope2",
				Audience: "https://api.example.com",
			},
			secretNamespace: "ns1",
			objects:         []client.Object{},
			expectedConfig: &command.Config{
				Hostname:                  "https://ca.example.com",
				APIPath:                   "/api/v1",
				AmbientCredentialScopes:   []string{"scope1", "scope2"},
				AmbientCredentialAudience: "https://api.example.com",
			},
		},
		{
			name: "success-no-auth-secret",
			issuerSpec: commandissuer.IssuerSpec{
				Hostname: "https://ca.example.com",
				APIPath:  "/api/v1",
			},
			secretNamespace: "ns1",
			objects:         []client.Object{},
			expectedConfig: &command.Config{
				Hostname:                  "https://ca.example.com",
				APIPath:                   "/api/v1",
				AmbientCredentialScopes:   []string{""},
				AmbientCredentialAudience: "",
			},
		},
		{
			name: "error-auth-secret-not-found",
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "missing-secret",
			},
			secretNamespace: "ns1",
			objects:         []client.Object{},
			expectedError:   errGetAuthSecret,
		},
		{
			name: "error-ca-secret-not-found",
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:     "https://ca.example.com",
				CaSecretName: "missing-ca-secret",
			},
			secretNamespace: "ns1",
			objects:         []client.Object{},
			expectedError:   errGetCaSecret,
		},
		{
			name: "error-ca-secret-key-not-found",
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:     "https://ca.example.com",
				CaSecretName: "ca-secret",
				CaBundleKey:  "ca.crt",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:              "https://ca.example.com",
				CaBundleConfigMapName: "missing-ca-bundle",
			},
			secretNamespace: "ns1",
			objects:         []client.Object{},
			expectedError:   errGetCaConfigMap,
		},
		{
			name: "error-ca-configmap-key-not-found",
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:              "https://ca.example.com",
				CaBundleConfigMapName: "ca-configmap",
				CaBundleKey:           "ca.crt",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "auth-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "auth-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "oauth-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "auth-secret",
			},
			secretNamespace: "ns1",
			objects: []client.Object{
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
			issuerSpec: commandissuer.IssuerSpec{
				Hostname:   "https://ca.example.com",
				SecretName: "auth-secret",
			},
			secretNamespace: "kube-system",
			objects: []client.Object{
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
	require.NoError(t, commandissuer.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeClient := fake.NewClientBuilder().
				WithScheme(scheme).
				WithObjects(tc.objects...).
				Build()

			// Create a minimal issuer with the test spec
			issuer := &commandissuer.Issuer{
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

// These tests cover the tenant-isolation rules for spec.serviceAccountRef. Several of them (enum, one-of, name)
// are also enforced by the CRD. However, we additionally exercise here with an invalid spec to prove
// the controller still rejects the spec even if the CRD validation is outdated, disabled or bypassed.
func TestValidateServiceAccountRef(t *testing.T) {
	const (
		issuerNS = "tenant-a"
		otherNS  = "tenant-b" // Another namespace to ensure tenant isolation is enforced
	)

	azure := &commandissuer.AzureIdentity{ClientID: "client", TenantID: "tenant"}
	gcp := &commandissuer.GCPIdentity{ServiceAccountEmail: "service-account@example.iam.gserviceaccount.com"}

	type testCase struct {
		name             string
		clusterScoped    bool
		spec             commandissuer.IssuerSpec
		expectedErrorMsg string // empty means the reference must be accepted
	}

	tests := []testCase{
		// no reference, legacy behavior untouched
		{
			name: "nil-ref-namespaced",
			spec: commandissuer.IssuerSpec{Hostname: "h", SecretName: "auth-secret"},
		},
		{
			name:          "nil-ref-cluster",
			clusterScoped: true,
			spec:          commandissuer.IssuerSpec{Hostname: "h"},
		},

		// --- namespace scoping (the core isolation guarantee) ---
		{
			name: "namespaced-ref-namespace-omitted",
			spec: commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa"}},
		},
		{
			name: "namespaced-ref-namespace-equals-own",
			spec: commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Namespace: issuerNS}},
		},
		{
			name:             "namespaced-ref-other-namespace-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Namespace: otherNS}},
			expectedErrorMsg: "own namespace",
		},
		{
			name:             "namespaced-ref-cluster-resource-namespace-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Namespace: "kube-system"}},
			expectedErrorMsg: "own namespace",
		},
		{
			// Namespace names are case-sensitive; a case variant is a different namespace.
			name:             "namespaced-ref-case-variant-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Namespace: "Tenant-A"}},
			expectedErrorMsg: "own namespace",
		},
		{
			// No trimming or normalisation: a padded value must not match.
			name:             "namespaced-ref-whitespace-padded-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Namespace: " tenant-a"}},
			expectedErrorMsg: "own namespace",
		},
		{
			name:          "cluster-ref-namespace-required",
			clusterScoped: true,
			spec:          commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa"}},

			expectedErrorMsg: "namespace is required",
		},
		{
			name:          "cluster-ref-explicit-namespace",
			clusterScoped: true,
			spec:          commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Namespace: otherNS}},
		},

		// --- ambiguous credential configuration ---
		{
			name:             "ref-with-secret-name-rejected",
			spec:             commandissuer.IssuerSpec{SecretName: "auth-secret", ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa"}},
			expectedErrorMsg: "mutually exclusive",
		},
		{
			name:             "cluster-ref-with-secret-name-rejected",
			clusterScoped:    true,
			spec:             commandissuer.IssuerSpec{SecretName: "auth-secret", ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Namespace: issuerNS}},
			expectedErrorMsg: "mutually exclusive",
		},

		// --- fallbacks for CRD validation that is missing or disabled ---
		{
			name:             "empty-name-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{}},
			expectedErrorMsg: "name is required",
		},
		{
			name:             "unknown-provider-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Provider: "aws"}},
			expectedErrorMsg: "unsupported provider",
		},
		{
			name:             "provider-case-variant-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Provider: "Azure"}},
			expectedErrorMsg: "unsupported provider",
		},
		{
			name:             "provider-azure-with-gcp-block-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Provider: "azure", GCP: gcp}},
			expectedErrorMsg: "gcp may only be set",
		},
		{
			name:             "provider-gcp-with-azure-block-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Provider: "gcp", Azure: azure}},
			expectedErrorMsg: "azure may only be set",
		},
		{
			name:             "no-provider-both-blocks-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Azure: azure, GCP: gcp}},
			expectedErrorMsg: "only one of azure or gcp",
		},
		{
			name:             "provider-azure-both-blocks-rejected",
			spec:             commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Provider: "azure", Azure: azure, GCP: gcp}},
			expectedErrorMsg: "only one of azure or gcp",
		},

		// --- valid combinations stay valid ---
		{
			name: "provider-azure-with-azure-block",
			spec: commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Provider: "azure", Azure: azure}},
		},
		{
			name: "provider-gcp-with-gcp-block",
			spec: commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Provider: "gcp", GCP: gcp}},
		},
		{
			name: "no-provider-azure-block-only",
			spec: commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Azure: azure}},
		},
		{
			name: "no-provider-gcp-block-only",
			spec: commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", GCP: gcp}},
		},
		{
			name: "provider-only-no-blocks",
			spec: commandissuer.IssuerSpec{ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Provider: "gcp"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var issuer commandissuer.IssuerLike
			if tc.clusterScoped {
				issuer = &commandissuer.ClusterIssuer{ObjectMeta: metav1.ObjectMeta{Name: "test"}, Spec: tc.spec}
			} else {
				issuer = &commandissuer.Issuer{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: issuerNS}, Spec: tc.spec}
			}

			err := validateServiceAccountRef(logr.Discard(), issuer)

			if tc.expectedErrorMsg == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, errInvalidServiceAccountRef)
			assert.Contains(t, err.Error(), tc.expectedErrorMsg)
		})
	}

}

// The namespace of a namespaced Issuer must come from the Issuer, not from the secret
// namespace. When the controller is not granted cluster-level secret access, the secret
// namespace is the cluster resource namespace for every Issuer, so comparing against it
// would let a tenant reference a ServiceAccount in that shared namespace.
func TestCommandConfigFromIssuerServiceAccountRefNamespace(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, commandissuer.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	tests := []struct {
		name             string
		refNamespace     string
		expectedErrorMsg string
	}{
		{name: "own-namespace-accepted", refNamespace: "tenant-a"},
		{name: "omitted-accepted", refNamespace: ""},
		{name: "secret-namespace-rejected", refNamespace: "kube-system", expectedErrorMsg: "own namespace"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuer := &commandissuer.Issuer{
				ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "tenant-a"},
				Spec: commandissuer.IssuerSpec{
					Hostname:          "https://ca.example.com",
					ServiceAccountRef: &commandissuer.ServiceAccountReference{Name: "sa", Namespace: tc.refNamespace},
				},
			}
			fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

			// secretNamespace differs from the Issuer's namespace, as with SecretAccessGrantedAtClusterLevel=false.
			config, err := commandConfigFromIssuer(context.Background(), fakeClient, issuer, "kube-system")

			if tc.expectedErrorMsg == "" {
				require.NoError(t, err)
				require.NotNil(t, config)
				return
			}
			require.Error(t, err)
			assert.ErrorIs(t, err, errInvalidServiceAccountRef)
			assert.Contains(t, err.Error(), tc.expectedErrorMsg)
			assert.Nil(t, config)
		})
	}
}

// A rejected reference must fail before any Secret or ConfigMap lookups. Pointing the spec at
// resources that do not exist proves the validation error wins over a lookup error.
func TestCommandConfigFromIssuerServiceAccountRefValidatedBeforeLookups(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, commandissuer.AddToScheme(scheme))
	require.NoError(t, corev1.AddToScheme(scheme))

	issuer := &commandissuer.Issuer{
		ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "tenant-a"},
		Spec: commandissuer.IssuerSpec{
			Hostname:              "https://ca.example.com",
			SecretName:            "missing-secret",
			CaBundleConfigMapName: "missing-configmap",
			ServiceAccountRef:     &commandissuer.ServiceAccountReference{Name: "sa"},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	config, err := commandConfigFromIssuer(context.Background(), fakeClient, issuer, "tenant-a")

	require.Error(t, err)
	assert.ErrorIs(t, err, errInvalidServiceAccountRef)
	assert.NotErrorIs(t, err, errGetAuthSecret)
	assert.NotErrorIs(t, err, errGetCaConfigMap)
	assert.Nil(t, config)
}
