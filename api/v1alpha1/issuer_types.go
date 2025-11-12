/*
Copyright © 2025 Keyfactor

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

package v1alpha1

import (
	"context"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// +kubebuilder:object:generate=false
type IssuerLike interface {
	GetStatus() *IssuerStatus
	GetSpec() *IssuerSpec
	IsClusterScoped() bool
	client.Object
}

var (
	_ IssuerLike = &Issuer{}
)

// IssuerSpec defines the desired state of Issuer
type IssuerSpec struct {
	// Hostname is the hostname of a Keyfactor Command instance.
	Hostname string `json:"hostname,omitempty"`

	// APIPath is the base path of the Command API. KeyfactorAPI by default
	// +kubebuilder:default:=KeyfactorAPI
	APIPath string `json:"apiPath,omitempty"`

	// The healthcheck configuration for the issuer. This configures the frequency at which the issuer will perform
	// a health check to determine issuer's connectivity to Command instance.
	// +kubebuilder:validation:Optional
	HealthCheck *HealthCheckConfig `json:"healthcheck,omitempty"`

	// EnrollmentPatternId is the ID of the enrollment pattern to use. Supported in Keyfactor Command 25.1 and later.
	// If both enrollment pattern and certificate template are specified, enrollment pattern will take precedence.
	// If EnrollmentPatternId and EnrollmentPatternName are both specified, EnrollmentPatternId will take precedence.
	// Enrollment will fail if the specified template is not compatible with the enrollment pattern.
	// Refer to the Keyfactor Command documentation for more information.
	EnrollmentPatternId int32 `json:"enrollmentPatternId,omitempty"`

	// EnrollmentPatternName is the name of the enrollment pattern to use. Supported in Keyfactor Command 25.1 and later.
	// If both enrollment pattern and certificate template are specified, enrollment pattern will take precedence.
	// If EnrollmentPatternId and EnrollmentPatternName are both specified, EnrollmentPatternId will take precedence.
	// Enrollment will fail if the specified template is not compatible with the enrollment pattern.
	// Refer to the Keyfactor Command documentation for more information.
	EnrollmentPatternName string `json:"enrollmentPatternName,omitempty"`

	// Deprecated. CertificateTemplate is the name of the certificate template to use. If using Keyfactor Command 25.1 or later, use EnrollmentPatternName or EnrollmentPatternId instead.
	// If both enrollment pattern and certificate template are specified, enrollment pattern will take precedence.
	// Enrollment will fail if the specified template is not compatible with the enrollment pattern.
	// Refer to the Keyfactor Command documentation for more information.
	CertificateTemplate string `json:"certificateTemplate,omitempty"`

	// OwnerRoleId is the ID of the security role assigned as the certificate owner.
	// The specified security role must be assigned to the authorized identity context.
	// If OwnerRoleId and OwnerRoleName are both specified, OwnerRoleId will take precedence.
	// This field is required if the enrollment pattern, certificate template, or system-wide settings has been configured as Required.
	// + optional
	OwnerRoleId int32 `json:"ownerRoleId,omitempty"`

	// OwnerRoleName is the name of the security role assigned as the certificate owner. This name must match the existing name of the security role.
	// The specified security role must be assigned to the authorized identity context.
	// If OwnerRoleId and OwnerRoleName are both specified, OwnerRoleId will take precedence.
	// This field is required if the enrollment pattern, certificate template, or system-wide settings has been configured as Required.
	// + optional
	OwnerRoleName string `json:"ownerRoleName,omitempty"`

	// CertificateAuthorityLogicalName is the logical name of the certificate authority to use
	// E.g. "Keyfactor Root CA" or "Intermediate CA"
	CertificateAuthorityLogicalName string `json:"certificateAuthorityLogicalName,omitempty"`

	// CertificateAuthorityHostname is the hostname associated with the Certificate Authority specified by
	// CertificateAuthorityLogicalName E.g. "ca.example.com"
	// +optional
	CertificateAuthorityHostname string `json:"certificateAuthorityHostname,omitempty"`

	// A reference to a K8s kubernetes.io/basic-auth Secret containing basic auth
	// credentials for the Command instance configured in Hostname. The secret must
	// be in the same namespace as the referent. If the
	// referent is a ClusterIssuer, the reference instead refers to the resource
	// with the given name in the configured 'cluster resource namespace', which
	// is set as a flag on the controller component (and defaults to the
	// namespace that the controller runs in).
	// +optional
	SecretName string `json:"commandSecretName,omitempty"`

	// The name of the secret containing the CA bundle to use when verifying
	// Command's server certificate. If specified, the CA bundle will be added to
	// the client trust roots for the Command issuer.
	// +optional
	CaSecretName string `json:"caSecretName,omitempty"`

	// A list of comma separated scopes used when requesting a Bearer token from an ambient token provider implied
	// by the environment, rather than by commandSecretName. For example, could be set to
	// api://{tenant ID}/.default when requesting an access token for Entra ID (DefaultAzureCredential). Has no
	// effect on OAuth 2.0 Client Credential configuration - please specify the scopes for this method in an Opaque secret.
	// +optional
	Scopes string `json:"scopes,omitempty"`

	// The audience value used when requesting a Bearer token from an ambient token provider implied
	// by the environment, rather than by commandSecretName. For example, could be set to
	// https://example.com when requesting an access token from Google's identity token provider. Ideally, this should be
	// the URL of your Command environment.Has no effect on OAuth 2.0 Client Credential configuration - please specify
	// the audience for this method in an Opaque secret.
	// +optional
	Audience string `json:"audience,omitempty"`
}

func (i *Issuer) GetStatus() *IssuerStatus {
	return &i.Status
}

func (i *Issuer) GetSpec() *IssuerSpec {
	return &i.Spec
}

func (i *Issuer) IsClusterScoped() bool {
	return false
}

// IssuerStatus defines the observed state of Issuer
type IssuerStatus struct {
	// List of status conditions to indicate the status of a CertificateRequest.
	// Known condition types are `Ready`.
	// +optional
	Conditions []IssuerCondition `json:"conditions,omitempty"`
}

func (is *IssuerStatus) SetCondition(ctx context.Context, conditionType IssuerConditionType, state ConditionStatus, reason, message string) {
	log := ctrl.LoggerFrom(ctx)
	var condition *IssuerCondition

	for i := range is.Conditions {
		if is.Conditions[i].Type == conditionType {
			condition = &is.Conditions[i]
			break
		}
	}

	// If the status object doesn't already have a conditionType, add it
	if condition == nil {
		condition = &IssuerCondition{
			Type: conditionType,
		}
		is.Conditions = append(is.Conditions, *condition)
		condition = &is.Conditions[len(is.Conditions)-1]
	}

	if condition.Status != state {
		log.Info(fmt.Sprintf("Changing %s Condition from %q -> %q; %q", conditionType, condition.Status, state, message))

		condition.Status = state
		now := metav1.Now()
		condition.LastTransitionTime = &now
	}
	condition.Reason = reason
	condition.Message = message
}

func (is *IssuerStatus) HasCondition(conditionType IssuerConditionType, state ConditionStatus) bool {
	for _, c := range is.Conditions {
		if c.Type == conditionType && c.Status == state {
			return true
		}
	}
	return false
}

func (is *IssuerStatus) UnsetCondition(conditionType IssuerConditionType) {
	conditions := is.Conditions
	for i, c := range conditions {
		if c.Type == conditionType {
			is.Conditions = append(conditions[:i], conditions[i+1:]...)
			return
		}
	}
}

//+kubebuilder:object:root=true
//+kubebuilder:subresource:status

// Issuer is the Schema for the issuers API
type Issuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   IssuerSpec   `json:"spec,omitempty"`
	Status IssuerStatus `json:"status,omitempty"`
}

//+kubebuilder:object:root=true

// IssuerList contains a list of Issuer
type IssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Issuer `json:"items"`
}

// IssuerCondition contains condition information for an Issuer.
type IssuerCondition struct {
	// Type of the condition, known values are ('Ready').
	Type IssuerConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown').
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

const (
	OAuthTokenURLKey     = "tokenUrl"
	OAuthClientIDKey     = "clientId"
	OAuthClientSecretKey = "clientSecret"
	OAuthScopesKey       = "scopes"
	OAuthAudienceKey     = "audience"
)

// IssuerConditionType represents an Issuer condition value.
type IssuerConditionType string

const (
	// IssuerConditionReady represents the fact that a given Issuer condition
	// is in ready state and able to issue certificates.
	// If the `status` of this condition is `False`, CertificateRequest controllers
	// should prevent attempts to sign certificates.
	IssuerConditionReady IssuerConditionType = "Ready"

	// IssuerConditionSupportsMetadata represents the fact that the connected Command platform supports
	// the pre-defined metadata fields that Command Issuer populates.
	IssuerConditionSupportsMetadata IssuerConditionType = "SupportsMetadata"
)

// ConditionStatus represents a condition's status.
// +kubebuilder:validation:Enum=True;False;Unknown
type ConditionStatus string

// These are valid condition statuses. "ConditionTrue" means a resource is in
// the condition; "ConditionFalse" means a resource is not in the condition;
// "ConditionUnknown" means kubernetes can't decide if a resource is in the
// condition or not. In the future, we could add other intermediate
// conditions, e.g. ConditionDegraded.
const (
	// ConditionTrue represents the fact that a given condition is true
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown
	ConditionUnknown ConditionStatus = "Unknown"
)

type HealthCheckConfig struct {
	// Determines whether to enable the health check when the issuer is healthy. Default: true
	Enabled bool `json:"enabled"`

	// The interval at which to health check the issuer when healthy. Defaults to 1 minute. Must not be less than "30s".
	// +kubebuilder:validation:Optional
	Interval *metav1.Duration `json:"interval,omitempty"`
}

func init() {
	SchemeBuilder.Register(&Issuer{}, &IssuerList{})
}
