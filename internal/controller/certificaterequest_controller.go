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
	"fmt"

	commandissuer "github.com/Keyfactor/command-cert-manager-issuer/api/v1alpha1"
	"github.com/Keyfactor/command-cert-manager-issuer/internal/command"
	cmutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
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
	Scheme                            *runtime.Scheme
	SignerBuilder                     command.SignerBuilder
	ClusterResourceNamespace          string
	SecretAccessGrantedAtClusterLevel bool
	Clock                             clock.Clock
	CheckApprovedCondition            bool
}

// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests,verbs=get;list;watch
// +kubebuilder:rbac:groups=cert-manager.io,resources=certificaterequests/status,verbs=get;update;patch
// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch

// Reconcile attempts to sign a CertificateRequest given the configuration provided and a configured
// Command signer instance.
func (r *CertificateRequestReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	meta := command.K8sMetadata{}

	// Get the CertificateRequest
	var certificateRequest cmapi.CertificateRequest
	if err := r.Get(ctx, req.NamespacedName, &certificateRequest); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info("CertificateRequest not found. ignoring.")
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

	log.Info("Starting CertificateRequest reconciliation run")

	// We now have a CertificateRequest that belongs to us so we are responsible
	// for updating its Ready condition.

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			setCertificateRequestReadyCondition(&certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, err.Error())
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
		setCertificateRequestReadyCondition(&certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonDenied, message)
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
		log.Info("Initializing Ready condition")
		setCertificateRequestReadyCondition(&certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonPending, "Initializing")
		return ctrl.Result{}, nil
	}

	// Ignore but log an error if the issuerRef.Kind is Unrecognized
	issuerGVK := commandissuer.GroupVersion.WithKind(certificateRequest.Spec.IssuerRef.Kind)
	issuerRO, err := r.Scheme.New(issuerGVK)
	if err != nil {
		err = fmt.Errorf("%w: %v", errIssuerRef, err)
		log.Error(err, "Unrecognized kind. Ignoring.")
		setCertificateRequestReadyCondition(&certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}
	issuer, ok := issuerRO.(commandissuer.IssuerLike)
	if !ok {
		err := fmt.Errorf("%w: unexpected type for issuer object: %T", errIssuerRef, issuerRO)
		log.Error(err, "Failed to cast to commandissuer.IssuerLike")
		setCertificateRequestReadyCondition(&certificateRequest, cmmeta.ConditionFalse, cmapi.CertificateRequestReasonFailed, err.Error())
		return ctrl.Result{}, nil
	}

	var secretNamespace string
	var issuerNamespace string

	// Create a Namespaced name for Issuer and a non-Namespaced name for ClusterIssuer
	switch {
	case issuer.IsClusterScoped():
		issuerNamespace = ""
		secretNamespace = r.ClusterResourceNamespace
		log = log.WithValues("clusterissuer", issuerNamespace)
		meta.ControllerKind = "clusterissuer"

	case !issuer.IsClusterScoped():
		issuerNamespace = certificateRequest.Namespace
		secretNamespace = certificateRequest.Namespace
		log = log.WithValues("issuer", issuerNamespace)
		meta.ControllerKind = "issuer"
	}

	// If SecretAccessGrantedAtClusterLevel is false, we always look for the Secret in the same namespace as the Issuer
	if !r.SecretAccessGrantedAtClusterLevel {
		secretNamespace = r.ClusterResourceNamespace
	}

	// Get the Issuer or ClusterIssuer
	err = r.Get(ctx, types.NamespacedName{
		Name:      certificateRequest.Spec.IssuerRef.Name,
		Namespace: issuerNamespace,
	}, issuer)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errGetIssuer, err)
	}

	if !issuer.GetStatus().HasCondition(commandissuer.IssuerConditionReady, commandissuer.ConditionTrue) {
		return ctrl.Result{}, errIssuerNotReady
	}

	config, err := commandConfigFromIssuer(ctx, r.Client, issuer, secretNamespace)
	if err != nil {
		return ctrl.Result{}, err
	}

	commandSigner, err := r.SignerBuilder(ctx, config)
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

	if value, exists := certificateRequest.Annotations["cert-manager.io/certificate-name"]; exists {
		meta.CertManagerCertificateName = value
	}

	signConfig := &command.SignConfig{
		CertificateTemplate:             issuer.GetSpec().CertificateTemplate,
		CertificateAuthorityLogicalName: issuer.GetSpec().CertificateAuthorityLogicalName,
		CertificateAuthorityHostname:    issuer.GetSpec().CertificateAuthorityHostname,
		Annotations:                     certificateRequest.GetAnnotations(),
	}

	if issuer.GetStatus().HasCondition(commandissuer.IssuerConditionSupportsMetadata, commandissuer.ConditionTrue) {
		signConfig.Meta = &meta
	}

	leaf, chain, err := commandSigner.Sign(ctx, certificateRequest.Spec.Request, signConfig)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errSignerSign, err)
	}
	certificateRequest.Status.Certificate = leaf
	certificateRequest.Status.CA = chain

	setCertificateRequestReadyCondition(&certificateRequest, cmmeta.ConditionTrue, cmapi.CertificateRequestReasonIssued, "Signed")
	return ctrl.Result{}, nil
}

func setCertificateRequestReadyCondition(cr *cmapi.CertificateRequest, status cmmeta.ConditionStatus, reason, message string) {
	cmutil.SetCertificateRequestCondition(
		cr,
		cmapi.CertificateRequestConditionReady,
		status,
		reason,
		message,
	)
}

// SetupWithManager registers the CertificateRequestReconciler with the controller manager.
// It configures controller-runtime to reconcile cert-manager CertificateRequests in the cluster.
func (r *CertificateRequestReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&cmapi.CertificateRequest{}).
		Complete(r)
}
