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
	"fmt"
)

const (
	ProviderAzure = "azure"
	ProviderGCP   = "gcp"

	// Annotations set on a ServiceAccount by the cluster's workload identity integration.
	AzureClientIDAnnotation     = "azure.workload.identity/client-id"
	AzureTenantIDAnnotation     = "azure.workload.identity/tenant-id"
	GCPServiceAccountAnnotation = "iam.gke.io/gcp-service-account"
)

var (
	errMissingServiceAccountRef = errors.New("serviceAccountRef is required")
	errInvalidIdentityConfig    = errors.New("invalid serviceAccountRef identity configuration")
	errServiceAccountLookup     = errors.New("failed to read the referenced ServiceAccount")
	errAmbiguousProvider        = errors.New("cannot determine cloud provider: ServiceAccount is annotated for more than one provider")
	errNoProviderResolved       = errors.New("cannot determine cloud provider")
	errMissingIdentity          = errors.New("missing cloud identity value")
)

// ServiceAccountRef identifies the ServiceAccount whose bound cloud identity is used, plus
// optional explicit values that take precedence over the ServiceAccount's annotations.
// Namespace must already be resolved by the caller (a namespaced Issuer's own namespace
// when the user omitted it).
type ServiceAccountRef struct {
	Name      string
	Namespace string
	Provider  string
	Azure     *AzureIdentity
	GCP       *GCPIdentity
}

type AzureIdentity struct {
	ClientID string
	TenantID string
}

type GCPIdentity struct {
	ServiceAccountEmail string
}

// ServiceAccountAnnotationGetter reads the annotations of a ServiceAccount. It is only
// called when the ref does not carry every value needed.
type ServiceAccountAnnotationGetter interface {
	GetServiceAccountAnnotations(ctx context.Context, namespace, name string) (map[string]string, error)
}

// ResolvedIdentity is the cloud identity a ServiceAccount should authenticate as.
// Exactly one of Azure or GCP is set, matching Provider.
type ResolvedIdentity struct {
	Provider string
	Azure    *AzureIdentity
	GCP      *GCPIdentity

	// Warnings are non-fatal findings the caller should log, such as a ServiceAccount
	// annotated for a different provider than the one explicitly selected.
	Warnings []string
}

// ResolveServiceAccountIdentity resolves the provider and identity values for ref.
//
// Precedence, highest first: explicit values on the ref, then the ServiceAccount's
// annotations, then (Azure tenant only) defaultAzureTenantID. An explicitly selected provider
// is never replaced by another one, and the pod's own ambient identity is never consulted:
// anything unresolved is an error.
func ResolveServiceAccountIdentity(ctx context.Context, ref *ServiceAccountRef, getter ServiceAccountAnnotationGetter, defaultAzureTenantID string) (*ResolvedIdentity, error) {
	if ref == nil {
		return nil, errMissingServiceAccountRef
	}
	if ref.Name == "" || ref.Namespace == "" {
		return nil, fmt.Errorf("%w: name and namespace are required", errInvalidIdentityConfig)
	}
	if err := ValidateIdentityConfig(ref); err != nil {
		return nil, err
	}

	var (
		annotations map[string]string
		fetched     bool
	)
	fetch := func() error {
		if fetched {
			return nil
		}
		a, err := getter.GetServiceAccountAnnotations(ctx, ref.Namespace, ref.Name)
		if err != nil {
			return fmt.Errorf("%w: %s/%s: %w", errServiceAccountLookup, ref.Namespace, ref.Name, err)
		}
		annotations, fetched = a, true
		return nil
	}

	provider := ref.Provider
	if provider == "" {
		switch {
		case ref.Azure != nil:
			provider = ProviderAzure
		case ref.GCP != nil:
			provider = ProviderGCP
		}
	}

	if provider == "" {
		if err := fetch(); err != nil {
			return nil, err
		}
		hasAzure := annotations[AzureClientIDAnnotation] != ""
		hasGCP := annotations[GCPServiceAccountAnnotation] != ""
		switch {
		case hasAzure && hasGCP:
			// If provider is not explicitly defined, having both Azure and GCP annotations is ambiguous.
			return nil, fmt.Errorf("%w: %s/%s; set provider explicitly", errAmbiguousProvider, ref.Namespace, ref.Name)
		case hasAzure:
			provider = ProviderAzure
		case hasGCP:
			provider = ProviderGCP
		default:
			// If no provider is explicitly defined and no relevant annotations are found, we cannot resolve the provider.
			return nil, fmt.Errorf("%w: ServiceAccount %s/%s has no %s or %s annotation; annotate it, or set provider and identity values on serviceAccountRef",
				errNoProviderResolved, ref.Namespace, ref.Name, AzureClientIDAnnotation, GCPServiceAccountAnnotation)
		}
	}

	resolved := &ResolvedIdentity{Provider: provider}

	switch provider {
	case ProviderAzure:
		var clientID, tenantID string
		if ref.Azure != nil {
			clientID, tenantID = ref.Azure.ClientID, ref.Azure.TenantID
		}
		// The ServiceAccount is only read when something is still missing. A tenant that is
		// not set explicitly is looked up before the default is applied.
		if clientID == "" || tenantID == "" {
			if err := fetch(); err != nil {
				return nil, err
			}
			if clientID == "" {
				clientID = annotations[AzureClientIDAnnotation]
			}
			if tenantID == "" {
				tenantID = annotations[AzureTenantIDAnnotation]
			}
		}
		if tenantID == "" {
			tenantID = defaultAzureTenantID
		}
		if clientID == "" {
			return nil, fmt.Errorf("%w: azure clientId for ServiceAccount %s/%s (set azure.clientId or annotate with %s)",
				errMissingIdentity, ref.Namespace, ref.Name, AzureClientIDAnnotation)
		}
		if tenantID == "" {
			return nil, fmt.Errorf("%w: azure tenantId for ServiceAccount %s/%s (set azure.tenantId, annotate with %s, or configure a default tenant)",
				errMissingIdentity, ref.Namespace, ref.Name, AzureTenantIDAnnotation)
		}
		resolved.Azure = &AzureIdentity{ClientID: clientID, TenantID: tenantID}

	case ProviderGCP:
		var email string
		if ref.GCP != nil {
			email = ref.GCP.ServiceAccountEmail
		}
		if email == "" {
			if err := fetch(); err != nil {
				return nil, err
			}
			email = annotations[GCPServiceAccountAnnotation]
		}
		if email == "" {
			return nil, fmt.Errorf("%w: gcp serviceAccountEmail for ServiceAccount %s/%s (set gcp.serviceAccountEmail or annotate with %s)",
				errMissingIdentity, ref.Namespace, ref.Name, GCPServiceAccountAnnotation)
		}
		resolved.GCP = &GCPIdentity{ServiceAccountEmail: email}
	}

	if fetched {
		// If we fetched annotations from the ServiceAccount, check for any that are irrelevant to the chosen provider and warn about them.
		switch {
		case provider == ProviderAzure && annotations[GCPServiceAccountAnnotation] != "":
			resolved.Warnings = append(resolved.Warnings, fmt.Sprintf("ServiceAccount %s/%s has a %s annotation, which is ignored because the provider is azure", ref.Namespace, ref.Name, GCPServiceAccountAnnotation))
		case provider == ProviderGCP && annotations[AzureClientIDAnnotation] != "":
			resolved.Warnings = append(resolved.Warnings, fmt.Sprintf("ServiceAccount %s/%s has a %s annotation, which is ignored because the provider is gcp", ref.Namespace, ref.Name, AzureClientIDAnnotation))
		}
	}

	return resolved, nil
}

// ValidateIdentityConfig checks the provider and identity-block consistency of ref: the
// provider must be known, azure and gcp are mutually exclusive, and a block must match the
// provider. It is the single source of these rules; the CRD enforces them at admission, the
// controller calls this as a fallback, and the resolver calls it so it is safe on its own.
func ValidateIdentityConfig(ref *ServiceAccountRef) error {
	switch ref.Provider {
	case "", ProviderAzure, ProviderGCP:
	default:
		return fmt.Errorf("%w: unsupported provider %q", errInvalidIdentityConfig, ref.Provider)
	}
	if ref.Azure != nil && ref.GCP != nil {
		return fmt.Errorf("%w: only one of azure or gcp may be set", errInvalidIdentityConfig)
	}
	if ref.Azure != nil && ref.Provider != "" && ref.Provider != ProviderAzure {
		return fmt.Errorf("%w: azure may only be set when provider is azure or unset", errInvalidIdentityConfig)
	}
	if ref.GCP != nil && ref.Provider != "" && ref.Provider != ProviderGCP {
		return fmt.Errorf("%w: gcp may only be set when provider is gcp or unset", errInvalidIdentityConfig)
	}
	return nil
}
