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
	"strings"
	"time"

	commandissuer "github.com/Keyfactor/command-cert-manager-issuer/api/v1alpha1"
	"github.com/Keyfactor/command-cert-manager-issuer/internal/command"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	issuerReadyConditionReason = "command-issuer.IssuerController.Reconcile"
	defaultHealthCheckInterval = time.Minute
)

var (
	errGetAuthSecret        = errors.New("failed to get Secret containing Issuer credentials")
	errGetCaSecret          = errors.New("caSecretName specified a name, but failed to get Secret containing CA certificate")
	errHealthCheckerBuilder = errors.New("failed to build the healthchecker")
	errHealthCheckerCheck   = errors.New("healthcheck failed")
)

// IssuerReconciler reconciles a Issuer object
type IssuerReconciler struct {
	client.Client
	Kind                              string
	ClusterResourceNamespace          string
	SecretAccessGrantedAtClusterLevel bool
	Scheme                            *runtime.Scheme
	HealthCheckerBuilder              command.HealthCheckerBuilder
}

//+kubebuilder:rbac:groups=command-issuer.keyfactor.com,resources=issuers;clusterissuers,verbs=get;list;watch
//+kubebuilder:rbac:groups=command-issuer.keyfactor.com,resources=issuers/status;clusterissuers/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=command-issuer.keyfactor.com,resources=issuers/finalizers,verbs=update

// newIssuer returns a new Issuer or ClusterIssuer object
func (r *IssuerReconciler) newIssuer() (commandissuer.IssuerLike, error) {
	issuerGVK := commandissuer.GroupVersion.WithKind(r.Kind)
	ro, err := r.Scheme.New(issuerGVK)
	if err != nil {
		return nil, err
	}
	return ro.(commandissuer.IssuerLike), nil
}

// Reconcile reconciles and updates the status of an Issuer or ClusterIssuer object
func (r *IssuerReconciler) Reconcile(ctx context.Context, req ctrl.Request) (result ctrl.Result, err error) {
	log := ctrl.LoggerFrom(ctx)

	issuer, err := r.newIssuer()
	if err != nil {
		log.Error(err, "Unrecognized issuer type")
		return ctrl.Result{}, nil
	}
	if err := r.Get(ctx, req.NamespacedName, issuer); err != nil {
		if err := client.IgnoreNotFound(err); err != nil {
			return ctrl.Result{}, fmt.Errorf("unexpected get error: %v", err)
		}
		log.Info(fmt.Sprintf("%s not found. Ignoring.", issuer.GetObjectKind().GroupVersionKind().Kind))
		return ctrl.Result{}, nil
	}

	log.Info(fmt.Sprintf("Starting %s reconciliation run", issuer.GetObjectKind().GroupVersionKind().Kind))

	// Always attempt to update the Ready condition
	defer func() {
		if err != nil {
			issuer.GetStatus().SetCondition(ctx, commandissuer.IssuerConditionReady, commandissuer.ConditionFalse, issuerReadyConditionReason, err.Error())
		}
		if updateErr := r.Status().Update(ctx, issuer); updateErr != nil {
			err = utilerrors.NewAggregate([]error{err, updateErr})
			result = ctrl.Result{}
		}
	}()

	var secretNamespace string

	switch {
	case issuer.IsClusterScoped():
		secretNamespace = r.ClusterResourceNamespace

	default:
		secretNamespace = req.Namespace
	}

	// If SecretAccessGrantedAtClusterLevel is false, we always look for the Secret in the same namespace as the Issuer
	if !r.SecretAccessGrantedAtClusterLevel {
		secretNamespace = r.ClusterResourceNamespace
	}

	config, err := commandConfigFromIssuer(ctx, r.Client, issuer, secretNamespace)
	if err != nil {
		return ctrl.Result{}, err
	}

	checker, err := r.HealthCheckerBuilder(ctx, config)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errHealthCheckerBuilder, err)
	}

	err = checker.Check(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errHealthCheckerCheck, err)
	}
	issuer.GetStatus().SetCondition(ctx, commandissuer.IssuerConditionReady, commandissuer.ConditionTrue, "Success", "Health check succeeded")

	metadataSupported, err := checker.CommandSupportsMetadata()
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("%w: %w", errHealthCheckerCheck, err)
	}

	switch {
	case metadataSupported:
		issuer.GetStatus().SetCondition(ctx, commandissuer.IssuerConditionSupportsMetadata, commandissuer.ConditionTrue, "Metadata fields are defined", "Connected Command platform has the Command Issuer metadata fields defined.")
	default:
		issuer.GetStatus().SetCondition(ctx, commandissuer.IssuerConditionSupportsMetadata, commandissuer.ConditionFalse, "Metadata fields are not defined", "Connected Command platform doesn't have the Command Issuer metadata fields defined.")
	}

	return ctrl.Result{RequeueAfter: defaultHealthCheckInterval}, nil
}

func commandConfigFromIssuer(ctx context.Context, c client.Client, issuer commandissuer.IssuerLike, secretNamespace string) (*command.Config, error) {
	log := ctrl.LoggerFrom(ctx)

	var basicAuth *command.BasicAuth
	var oauth *command.OAuth

	// The SecretName is optional since the user may elect to use ambient credentials for scenarios like Workload Identity.
	if issuer.GetSpec().SecretName != "" {
		var authSecret corev1.Secret
		log.Info("Fetching commandSecret from ns", "name", issuer.GetSpec().SecretName, "namespace", secretNamespace)
		err := c.Get(ctx, types.NamespacedName{
			Name:      issuer.GetSpec().SecretName,
			Namespace: secretNamespace,
		}, &authSecret)
		if err != nil {
			return nil, fmt.Errorf("%w, secret name: %s, reason: %w", errGetAuthSecret, issuer.GetSpec().SecretName, err)
		}

		switch {
		case authSecret.Type == corev1.SecretTypeOpaque:
			// We expect auth credentials for a client credential OAuth2.0 flow if the secret type is opaque
			tokenURL, ok := authSecret.Data[commandissuer.OAuthTokenURLKey]
			if !ok {
				return nil, fmt.Errorf("%w: %s", errGetAuthSecret, "found secret with no tokenUrl")
			}
			clientID, ok := authSecret.Data[commandissuer.OAuthClientIDKey]
			if !ok {
				return nil, fmt.Errorf("%w: %s", errGetAuthSecret, "found secret with no clientId")
			}
			clientSecret, ok := authSecret.Data[commandissuer.OAuthClientSecretKey]
			if !ok {
				return nil, fmt.Errorf("%w: %s", errGetAuthSecret, "found secret with no clientSecret")
			}
			oauth = &command.OAuth{
				TokenURL:     string(tokenURL),
				ClientID:     string(clientID),
				ClientSecret: string(clientSecret),
			}
			scopes, ok := authSecret.Data[commandissuer.OAuthScopesKey]
			if ok {
				oauth.Scopes = strings.Split(string(scopes), ",")
			}
			audience, ok := authSecret.Data[commandissuer.OAuthAudienceKey]
			if ok {
				oauth.Audience = string(audience)
			}
			log.Info("Found oauth client credentials in secret", "commandSecretName", issuer.GetSpec().SecretName, "type", authSecret.Type)

		case authSecret.Type == corev1.SecretTypeBasicAuth:
			username, ok := authSecret.Data[corev1.BasicAuthUsernameKey]
			if !ok {
				return nil, fmt.Errorf("%w: %s", errGetAuthSecret, "found basic auth secret with no username")
			}
			password, ok := authSecret.Data[corev1.BasicAuthPasswordKey]
			if !ok {
				return nil, fmt.Errorf("%w: %s", errGetAuthSecret, "found basic auth secret with no password")
			}

			basicAuth = &command.BasicAuth{
				Username: string(username),
				Password: string(password),
			}
			log.Info("Found basic auth credentials in secret", "commandSecretName", issuer.GetSpec().SecretName, "type", authSecret.Type)

		default:
			return nil, fmt.Errorf("%w: %s", errGetAuthSecret, "found secret with unsupported type")
		}
	}

	var caSecret corev1.Secret
	// If the CA secret name is not specified, we will not attempt to retrieve it
	if issuer.GetSpec().CaSecretName != "" {
		err := c.Get(ctx, types.NamespacedName{
			Name:      issuer.GetSpec().CaSecretName,
			Namespace: secretNamespace,
		}, &caSecret)
		if err != nil {
			return nil, fmt.Errorf("%w, secret name: %s, reason: %w", errGetCaSecret, issuer.GetSpec().CaSecretName, err)
		}
	}

	var caCertBytes []byte
	// There is no requirement that the CA certificate is stored under a specific
	// key in the secret, so we can just iterate over the map and effectively select
	// the last value in the map
	for _, bytes := range caSecret.Data {
		caCertBytes = bytes
	}

	return &command.Config{
		Hostname:                  issuer.GetSpec().Hostname,
		APIPath:                   issuer.GetSpec().APIPath,
		CaCertsBytes:              caCertBytes,
		BasicAuth:                 basicAuth,
		OAuth:                     oauth,
		AmbientCredentialScopes:   strings.Split(issuer.GetSpec().Scopes, ","),
		AmbientCredentialAudience: issuer.GetSpec().Audience,
	}, nil
}

// SetupWithManager registers the IssuerReconciler with the controller manager.
// It configures controller-runtime to reconcile Keyfactor Command Issuers/ClusterIssuers in the cluster.
func (r *IssuerReconciler) SetupWithManager(mgr ctrl.Manager) error {
	issuerType, err := r.newIssuer()
	if err != nil {
		return err
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(issuerType).
		Complete(r)
}
