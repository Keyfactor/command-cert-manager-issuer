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

package controllers

import (
	"context"
	"errors"
	"github.com/Keyfactor/command-issuer/internal/issuer/signer"
	issuerutil "github.com/Keyfactor/command-issuer/internal/issuer/util"
	logrtesting "github.com/go-logr/logr/testr"
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
	"testing"

	commandissuer "github.com/Keyfactor/command-issuer/api/v1alpha1"
)

type fakeHealthChecker struct {
	errCheck error
}

func (o *fakeHealthChecker) Check() error {
	return o.errCheck
}

func TestIssuerReconcile(t *testing.T) {
	type testCase struct {
		kind                         string
		name                         types.NamespacedName
		objects                      []client.Object
		healthCheckerBuilder         signer.HealthCheckerBuilder
		clusterResourceNamespace     string
		expectedResult               ctrl.Result
		expectedError                error
		expectedReadyConditionStatus commandissuer.ConditionStatus
	}

	tests := map[string]testCase{
		"success-issuer": {
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
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			healthCheckerBuilder: func(context.Context, *commandissuer.IssuerSpec, map[string][]byte, map[string][]byte) (signer.HealthChecker, error) {
				return &fakeHealthChecker{}, nil
			},
			expectedReadyConditionStatus: commandissuer.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"success-clusterissuer": {
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
					ObjectMeta: metav1.ObjectMeta{
						Name:      "clusterissuer1-credentials",
						Namespace: "kube-system",
					},
				},
			},
			healthCheckerBuilder: func(context.Context, *commandissuer.IssuerSpec, map[string][]byte, map[string][]byte) (signer.HealthChecker, error) {
				return &fakeHealthChecker{}, nil
			},
			clusterResourceNamespace:     "kube-system",
			expectedReadyConditionStatus: commandissuer.ConditionTrue,
			expectedResult:               ctrl.Result{RequeueAfter: defaultHealthCheckInterval},
		},
		"issuer-kind-Unrecognized": {
			kind: "UnrecognizedType",
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
		},
		"issuer-not-found": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
		},
		"issuer-missing-ready-condition": {
			name: types.NamespacedName{Namespace: "ns1", Name: "issuer1"},
			objects: []client.Object{
				&commandissuer.Issuer{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1",
						Namespace: "ns1",
					},
				},
			},
			expectedReadyConditionStatus: commandissuer.ConditionUnknown,
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
						},
					},
				},
			},
			expectedError:                errGetAuthSecret,
			expectedReadyConditionStatus: commandissuer.ConditionFalse,
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
						},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			healthCheckerBuilder: func(context.Context, *commandissuer.IssuerSpec, map[string][]byte, map[string][]byte) (signer.HealthChecker, error) {
				return nil, errors.New("simulated health checker builder error")
			},
			expectedError:                errHealthCheckerBuilder,
			expectedReadyConditionStatus: commandissuer.ConditionFalse,
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
						},
					},
				},
				&corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "issuer1-credentials",
						Namespace: "ns1",
					},
				},
			},
			healthCheckerBuilder: func(context.Context, *commandissuer.IssuerSpec, map[string][]byte, map[string][]byte) (signer.HealthChecker, error) {
				return &fakeHealthChecker{errCheck: errors.New("simulated health check error")}, nil
			},
			expectedError:                errHealthCheckerCheck,
			expectedReadyConditionStatus: commandissuer.ConditionFalse,
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
				Build()
			if tc.kind == "" {
				tc.kind = "Issuer"
			}
			controller := IssuerReconciler{
				Kind:                              tc.kind,
				Client:                            fakeClient,
				ConfigClient:                      NewFakeConfigClient(fakeClient),
				Scheme:                            scheme,
				HealthCheckerBuilder:              tc.healthCheckerBuilder,
				ClusterResourceNamespace:          tc.clusterResourceNamespace,
				SecretAccessGrantedAtClusterLevel: true,
			}
			result, err := controller.Reconcile(
				ctrl.LoggerInto(context.TODO(), logrtesting.New(t)),
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
				_, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)
				require.NoError(t, err)
				assertIssuerHasReadyCondition(t, tc.expectedReadyConditionStatus, issuerStatus)
			}
		})
	}
}

func assertIssuerHasReadyCondition(t *testing.T, status commandissuer.ConditionStatus, issuerStatus *commandissuer.IssuerStatus) {
	condition := issuerutil.GetReadyCondition(issuerStatus)
	if !assert.NotNil(t, condition, "Ready condition not found") {
		return
	}
	assert.Equal(t, issuerReadyConditionReason, condition.Reason, "unexpected condition reason")
	assert.Equal(t, status, condition.Status, "unexpected condition status")
}
