/*
Copyright 2023 Keyfactor.

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
	"fmt"
	commandissuer "github.com/Keyfactor/command-issuer/api/v1alpha1"
	"github.com/Keyfactor/command-issuer/internal/issuer/signer"
	issuerutil "github.com/Keyfactor/command-issuer/internal/issuer/util"
	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/utils/clock"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
)

var (
	errIssuerRef      = errors.New("error interpreting issuerRef")
	errGetIssuer      = errors.New("error getting issuer")
	errIssuerNotReady = errors.New("issuer is not ready")
	errSignerBuilder  = errors.New("failed to build the signer")
	errSignerSign     = errors.New("failed to sign")
)

type CertificateRequestReconciler struct {
	client.Client
	Scheme                   *runtime.Scheme
	SignerBuilder            signer.CommandSignerBuilder
	ClusterResourceNamespace string

	Clock                  clock.Clock
	CheckApprovedCondition bool
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	meta := signer.K8sMetadata{}

	// Get the CertificateRequest
	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("Not found. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequests if issuerRef doesn't match group
	if certificateRequest.Spec.IssuerRef.Group != commandissuer.GroupVersion.Group {
		log.Info("Foreign group. Ignoring.", "group", certificateRequest.Spec.IssuerRef.Group)
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if it is already Ready
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		log.Info("CertificateRequest is Ready. Ignoring.")
		return ctrl.Result{}, nil
	}

	// Ignore CertificateRequest if it is already Failed
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonFailed,
	}) {
		log.Info("CertificateRequest is Failed. Ignoring.")
		return ctrl.Result{}, nil
	}
	// Ignore CertificateRequest if it already has a Denied Ready Reason
	if cmutil.CertificateRequestHasCondition(&certificateRequest, cmapi.CertificateRequestCondition{
		Type:   cmapi.CertificateRequestConditionReady,
		Status: cmmeta.ConditionFalse,
		Reason: cmapi.CertificateRequestReasonDenied,
	}) {
		log.Info("CertificateRequest already has a Ready condition with Denied Reason. Ignoring.")
		return ctrl.Result{}, nil
	}

	// We now have a CertificateRequest that belongs to us so we are responsible
	// for updating its Ready condition.
	setReadyCondition := func(status cmmeta.ConditionStatus, reason, message string) {
		cmutil.SetCertificateRequestCondition(
			&certificateRequest,
			cmapi.CertificateRequestConditionReady,
			status,
			reason,
			message,
		)
	}

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, err.Error())
		}
		if updateErr := r.Status().Update(ctx, &certificateRequest); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	// If CertificateRequest has been denied, mark the CertificateRequest as
	// Ready=Denied and set FailureTime if not already.
	if cmutil.CertificateRequestIsDenied(&certificateRequest) {
		log.Info("CertificateRequest has been denied yet. Marking as failed.")

		if certificateRequest.Status.FailureTime == nil {
			nowTime := metav1.NewTime(r.Clock.Now())
			certificateRequest.Status.FailureTime = &nowTime
		}

		message := "The CertificateRequest was denied by an approval controller"
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, message)
		return ctrl.Result{}, nil
	}

	if r.CheckApprovedCondition {
		// If CertificateRequest has not been approved, exit early.
		if !cmutil.CertificateRequestIsApproved(&certificateRequest) {
			log.Info("CertificateRequest has not been approved yet. Ignoring.")
			return ctrl.Result{}, nil
		}
	}

	// Add a Ready condition if one does not already exist
	if ready := cmutil.GetCertificateRequestCondition(&certificateRequest, cmapi.CertificateRequestConditionReady); ready == nil {
		log.Info("Initialising Ready condition")
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Initialising")
		return ctrl.Result{}, nil
	}

	// Ignore but log an error if the issuerRef.Kind is Unrecognized
	issuerGVK := commandissuer.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		err = fmt.Errorf("%w: %v", errIssuerRef, err)
		log.Error(err, "Unrecognized kind. Ignoring.")
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}
	issuer := issuerRO.(client.Object)
	// Create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	issuerName := types.NamespacedName{
		Name: certificateRequest.Spec.IssuerRef.Name,
	}
	var secretNamespace string
	switch t := issuer.(type) {
	case *commandissuer.Issuer:
		issuerName.Namespace = certificateRequest.Namespace
		secretNamespace = certificateRequest.Namespace
		log = log.WithValues("issuer", issuerName)
		meta.ControllerKind = "issuer"
	case *commandissuer.ClusterIssuer:
		secretNamespace = r.ClusterResourceNamespace
		log = log.WithValues("clusterissuer", issuerName)
	default:
		err := fmt.Errorf("unexpected issuer type: %v", t)
		log.Error(err, "The issuerRef referred to a registered Kind which is not yet handled. Ignoring.")
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}

	// Get the Issuer or ClusterIssuer
	if err := r.Get(ctx, issuerName, issuer); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errGetIssuer, err)
	}

	issuerSpec, issuerStatus, err := issuerutil.GetSpecAndStatus(issuer)
	if err != nil {
		log.Error(err, "Unable to get the IssuerStatus. Ignoring.")
		setReadyCondition(cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}

	if !issuerutil.IsReady(issuerStatus) {
		return ctrl.Result{}, errIssuerNotReady
	}

	authSecretName := types.NamespacedName{
		Name:      issuerSpec.SecretName,
		Namespace: secretNamespace,
	}

	var authSecret corev1.Secret
	if err := r.Get(ctx, authSecretName, &authSecret); err != nil {
		return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetAuthSecret, authSecretName, err)
	}

	// Retrieve the CA certificate secret
	caSecretName := types.NamespacedName{
		Name:      issuerSpec.CaSecretName,
		Namespace: authSecretName.Namespace,
	}

	var caSecret corev1.Secret
	if issuerSpec.CaSecretName != "" {
		// If the CA secret name is not specified, we will not attempt to retrieve it
		err = r.Get(ctx, caSecretName, &caSecret)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("%w, secret name: %s, reason: %v", errGetCaSecret, caSecretName, err)
		}
	}

	commandSigner, err := r.SignerBuilder(ctx, issuerSpec, certificateRequest.GetAnnotations(), authSecret.Data, caSecret.Data)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerBuilder, err)
	}

	// Assign metadata
	meta.ControllerNamespace = r.ClusterResourceNamespace
	// meta.ControllerKind found above
	meta.ControllerResourceGroupName = commandissuer.GroupVersion.Group
	meta.IssuerName = certificateRequest.Spec.IssuerRef.Name
	meta.IssuerNamespace = certificateRequest.Namespace
	meta.ControllerReconcileId = string(controller.ReconcileIDFromContext(ctx))
	meta.CertificateSigningRequestNamespace = certificateRequest.Namespace

	leaf, chain, err := commandSigner.Sign(ctx, certificateRequest.Spec.Request, meta)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %v", errSignerSign, err)
	}
	certificateRequest.Status.Certificate = leaf
	certificateRequest.Status.CA = chain

	setReadyCondition(cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Signed")
	return ctrl.Result{}, nil
}

func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
