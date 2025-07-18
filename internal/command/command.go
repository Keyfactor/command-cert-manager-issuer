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

package command

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	commandsdk "github.com/Keyfactor/keyfactor-go-client-sdk/v25"
	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	cmpki "github.com/cert-manager/cert-manager/pkg/util/pki"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// Keyfactor enrollment PEM format
	enrollmentPEMFormat             = "PEM"
	commandMetadataAnnotationPrefix = "metadata.command-issuer.keyfactor.com/"
)

var (
	errInvalidConfig                    = errors.New("invalid config")
	errInvalidSignerConfig              = errors.New("invalid signer config")
	errInvalidCSR                       = errors.New("csr is invalid")
	errCommandEnrollmentFailure         = errors.New("command enrollment failure")
	errEnrollmentPatternFailure         = errors.New("enrollment pattern failure")
	errTokenFetchFailure                = errors.New("couldn't fetch bearer token")
	errAmbientCredentialCreationFailure = errors.New("failed to obtain ambient credentials")
)

type K8sMetadata struct {
	ControllerNamespace                string
	ControllerKind                     string
	ControllerResourceGroupName        string
	IssuerName                         string
	IssuerNamespace                    string
	ControllerReconcileId              string
	CertificateSigningRequestNamespace string
	CertManagerCertificateName         string
}

type HealthCheckerBuilder func(context.Context, *Config) (HealthChecker, error)
type HealthChecker interface {
	Check(context.Context) error
	CommandSupportsMetadata() (bool, error)
}

type SignerBuilder func(context.Context, *Config) (Signer, error)
type Signer interface {
	Sign(context.Context, []byte, *SignConfig) ([]byte, []byte, error)
}

type newCommandClientFunc func(*auth_providers.Server) (*commandsdk.APIClient, error)

type signer struct {
	client Client
}

type Config struct {
	Hostname                  string
	APIPath                   string
	CaCertsBytes              []byte
	BasicAuth                 *BasicAuth
	OAuth                     *OAuth
	AmbientCredentialScopes   []string
	AmbientCredentialAudience string
}

func (c *Config) validate() error {
	if c.Hostname == "" {
		return fmt.Errorf("%w: hostname is required", errInvalidConfig)
	}
	if c.APIPath == "" {
		return fmt.Errorf("%w: apiPath is required", errInvalidConfig)
	}

	// Validate the optional BasicAuth fields if BasicAuth is provided
	if err := c.BasicAuth.validate(); err != nil {
		return err
	}

	// Validate the optional OAuth fields if OAuth is provided
	if err := c.OAuth.validate(); err != nil {
		return err
	}

	return nil
}

type BasicAuth struct {
	Username string
	Password string
}

func (b *BasicAuth) validate() error {
	if b == nil {
		return nil
	}
	if b.Username == "" {
		return fmt.Errorf("%w: username is required", errInvalidConfig)
	}
	if b.Password == "" {
		return fmt.Errorf("%w: password is required", errInvalidConfig)
	}
	return nil
}

type OAuth struct {
	TokenURL     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	Audience     string
}

func (o *OAuth) validate() error {
	if o == nil {
		return nil
	}
	if o.TokenURL == "" {
		return fmt.Errorf("%w: tokenURL is required", errInvalidConfig)
	}
	if o.ClientID == "" {
		return fmt.Errorf("%w: clientID is required", errInvalidConfig)
	}
	if o.ClientSecret == "" {
		return fmt.Errorf("%w: clientSecret is required", errInvalidConfig)
	}
	return nil
}

func newServerConfig(ctx context.Context, config *Config) (*auth_providers.Server, error) {
	log := log.FromContext(ctx)

	if config == nil {
		return nil, fmt.Errorf("%w: nil config - this is a bug", errInvalidConfig)
	}

	var server *auth_providers.Server

	config.APIPath = strings.TrimLeft(config.APIPath, "/")
	config.APIPath = strings.TrimRight(config.APIPath, "/")

	authConfig := auth_providers.CommandAuthConfig{}
	authConfig.WithCommandHostName(config.Hostname)
	authConfig.WithCommandAPIPath(config.APIPath)
	authConfig.WithCommandCACert(string(config.CaCertsBytes))

	nonAmbientCredentialsConfigured := false

	if config.BasicAuth != nil {
		log.Info("Using basic auth credential source")

		basicAuthConfig := auth_providers.NewBasicAuthAuthenticatorBuilder().
			WithUsername(config.BasicAuth.Username).
			WithPassword(config.BasicAuth.Password)
		basicAuthConfig.CommandAuthConfig = authConfig
		server = basicAuthConfig.GetServerConfig()

		nonAmbientCredentialsConfigured = true
	}

	if config.OAuth != nil {
		log.Info("Using OAuth credential source")

		oauthConfig := auth_providers.NewOAuthAuthenticatorBuilder().
			WithTokenUrl(config.OAuth.TokenURL).
			WithClientId(config.OAuth.ClientID).
			WithClientSecret(config.OAuth.ClientSecret)

		if len(config.OAuth.Scopes) > 0 {
			oauthConfig.WithScopes(config.OAuth.Scopes)
		}
		if config.OAuth.Audience != "" {
			oauthConfig.WithAudience(config.OAuth.Audience)
		}

		oauthConfig.CommandAuthConfig = authConfig
		server = oauthConfig.GetServerConfig()

		nonAmbientCredentialsConfigured = true
	}

	// If direct basic-auth/OAuth credentials were configured, continue. Otherwise,
	// we look for ambient credentials configured on the environment where we're running.
	if !nonAmbientCredentialsConfigured {
		source := getAmbientTokenCredentialSource()
		if source == nil {
			log.Info("no direct credentials provided; attempting to use ambient credentials. trying Azure DefaultAzureCredential first")

			var err error
			source, err = newAzureDefaultCredentialSource(ctx, config.AmbientCredentialScopes)
			if err != nil {
				log.Info("couldn't obtain Azure DefaultAzureCredential. trying GCP ApplicationDefaultCredentials", "error", err)

				var innerErr error
				source, innerErr = newGCPDefaultCredentialSource(ctx, config.AmbientCredentialAudience, config.AmbientCredentialScopes)
				if innerErr != nil {
					return nil, fmt.Errorf("%w: azure err: %w. gcp err: %w", errAmbientCredentialCreationFailure, err, innerErr)
				}
			}

			// Set the credential source globally
			setAmbientTokenCredentialSource(source)
		}

		token, err := source.GetAccessToken(ctx)
		if err != nil {
			return nil, err
		}

		oauthConfig := auth_providers.NewOAuthAuthenticatorBuilder().
			WithAccessToken(token).
			WithCaCertificatePath("")
		oauthConfig.CommandAuthConfig = authConfig

		server = oauthConfig.GetServerConfig()
	}

	log.Info("Configuration was valid - Successfully generated server config", "authMethod", server.AuthType, "hostname", server.Host, "apiPath", server.APIPath)
	return server, nil
}

type SignConfig struct {
	CertificateTemplate             string // Deprecated, use EnrollmentPatternName or EnrollmentPatternId instead
	EnrollmentPatternId             int32
	EnrollmentPatternName           string
	CertificateAuthorityLogicalName string
	CertificateAuthorityHostname    string
	Meta                            *K8sMetadata
	Annotations                     map[string]string
}

func (s *SignConfig) validate() error {
	if s.CertificateTemplate == "" && s.EnrollmentPatternName == "" && s.EnrollmentPatternId == 0 {
		return errors.New("either certificateTemplate, enrollmentPatternName, or enrollmentPatternId must be specified")
	}
	if s.CertificateAuthorityLogicalName == "" {
		return errors.New("certificateAuthorityLogicalName is required")
	}
	return nil
}

func newInternalSigner(ctx context.Context, config *Config, newClientFunc newCommandClientFunc) (*signer, error) {
	if config == nil {
		return nil, fmt.Errorf("%w: newClientFunc hook is nil - this is a bug. please report this to the Command authors", errInvalidConfig)
	}
	log := log.FromContext(ctx)
	s := &signer{}

	err := config.validate()
	if err != nil {
		return nil, err
	}

	serverConfig, err := newServerConfig(ctx, config)
	if err != nil {
		return nil, err
	}

	client, err := newClientFunc(serverConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create new Command API client: %w", err)
	}

	adapter := &clientAdapter{
		enrollCSR:             client.V1.EnrollmentApi.CreateEnrollmentCSRExecute,
		getAllMetadataFields:  client.V1.MetadataFieldApi.GetMetadataFieldsExecute,
		getEnrollmentPatterns: client.V1.EnrollmentPatternApi.GetEnrollmentPatternsExecute,
		testConnection:        client.V1.AuthClient.Authenticate,
	}

	log.Info("Successfully generated Command client")
	s.client = adapter

	return s, nil
}

func NewHealthChecker(ctx context.Context, config *Config) (HealthChecker, error) {
	return newInternalSigner(ctx, config, commandsdk.NewAPIClient)
}

func NewSignerBuilder(ctx context.Context, config *Config) (Signer, error) {
	return newInternalSigner(ctx, config, commandsdk.NewAPIClient)
}

// Check implements HealthChecker.
func (s *signer) Check(ctx context.Context) error {
	err := s.client.TestConnection()
	if err != nil {
		return fmt.Errorf("failed to check status of connected Command instance: %w", err)
	}
	return nil
}

// CommandSupportsMetadata implements HealthChecker.
func (s *signer) CommandSupportsMetadata() (bool, error) {
	existingFields, _, err := s.client.GetAllMetadataFields(v1.ApiGetMetadataFieldsRequest{})
	if err != nil {
		return false, fmt.Errorf("failed to fetch metadata fields from connected Command instance: %w", err)
	}

	expectedFieldsSlice := []string{
		CommandMetaControllerNamespace,
		CommandMetaControllerKind,
		CommandMetaControllerResourceGroupName,
		CommandMetaIssuerName,
		CommandMetaIssuerNamespace,
		CommandMetaControllerReconcileId,
		CommandMetaCertificateSigningRequestNamespace,
	}

	// Create a lookup map (set) of existing field names
	existingFieldSet := make(map[string]struct{}, len(existingFields))
	for _, field := range existingFields {
		name := field.Name.Get()
		existingFieldSet[*name] = struct{}{}
	}

	// Check that every expected field is present
	for _, expectedField := range expectedFieldsSlice {
		if _, found := existingFieldSet[expectedField]; !found {
			// As soon as one recommended field is missing, return false
			return false, nil
		}
	}

	// If we've made it here, all required metadata fields are present
	return true, nil
}

const (
	CommandMetaControllerNamespace                = "Controller-Namespace"
	CommandMetaControllerKind                     = "Controller-Kind"
	CommandMetaControllerResourceGroupName        = "Controller-Resource-Group-Name"
	CommandMetaIssuerName                         = "Issuer-Name"
	CommandMetaIssuerNamespace                    = "Issuer-Namespace"
	CommandMetaControllerReconcileId              = "Controller-Reconcile-Id"
	CommandMetaCertificateSigningRequestNamespace = "Certificate-Signing-Request-Namespace"
)

// Sign implements Signer.
func (s *signer) Sign(ctx context.Context, csrBytes []byte, config *SignConfig) ([]byte, []byte, error) {
	k8sLog := log.FromContext(ctx)

	err := config.validate()
	if err != nil {
		return nil, nil, err
	}

	// Override defaults from annotations
	if value, exists := config.Annotations["command-issuer.keyfactor.com/certificateTemplate"]; exists {
		k8sLog.Info(fmt.Sprintf("Using certificateTemplate %q from annotations", value))
		config.CertificateTemplate = value
	}
	if value, exists := config.Annotations["command-issuer.keyfactor.com/certificateAuthorityLogicalName"]; exists {
		k8sLog.Info(fmt.Sprintf("Using certificateAuthorityLogicalName %q from annotations", value))
		config.CertificateAuthorityLogicalName = value
	}
	if value, exists := config.Annotations["command-issuer.keyfactor.com/certificateAuthorityHostname"]; exists {
		k8sLog.Info(fmt.Sprintf("Using certificateAuthorityHostname %q from annotations", value))
		config.CertificateAuthorityHostname = value
	}
	if value, exists := config.Annotations["command-issuer.keyfactor.com/enrollmentPatternId"]; exists {
		k8sLog.Info(fmt.Sprintf("Using enrollmentPatternId %q from annotations", value))
		conv, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: failed to parse enrollmentPatternId from annotations: %s", errInvalidSignerConfig, err)
		}
		config.EnrollmentPatternId = int32(conv)
	}
	if value, exists := config.Annotations["command-issuer.keyfactor.com/enrollmentPatternName"]; exists {
		k8sLog.Info(fmt.Sprintf("Using enrollmentPatternName %q from annotations", value))
		config.EnrollmentPatternName = value
	}

	k8sLog.Info(fmt.Sprintf("Using certificate template %q and certificate authority %q (%s) and enrollment pattern ID %d and enrollment pattern name %s", config.CertificateTemplate, config.CertificateAuthorityLogicalName, config.CertificateAuthorityHostname, config.EnrollmentPatternId, config.EnrollmentPatternName))

	csr, err := parseCSR(csrBytes)
	if err != nil {
		k8sLog.Error(err, "failed to parse CSR")
		return nil, nil, err
	}

	// Log the common metadata of the CSR
	k8sLog.Info(fmt.Sprintf("CSR has Common Name %q with %d DNS SANs, %d IP SANs, and %d URI SANs", csr.Subject.CommonName, len(csr.DNSNames), len(csr.IPAddresses), len(csr.URIs)))

	// Print the SANs
	for _, dnsName := range csr.DNSNames {
		k8sLog.Info(fmt.Sprintf("DNS SAN: %s", dnsName))
	}

	for _, ipAddress := range csr.IPAddresses {
		k8sLog.Info(fmt.Sprintf("IP SAN: %s", ipAddress.String()))
	}

	for _, uri := range csr.URIs {
		k8sLog.Info(fmt.Sprintf("URI SAN: %s", uri.String()))
	}

	req := v1.ApiCreateEnrollmentCSRRequest{}
	req = req.XCertificateformat(enrollmentPEMFormat)

	var template *string = nil
	var enrollmentPatternId *int32 = nil

	// Populate certificate template if defined
	if config.CertificateTemplate != "" {
		k8sLog.Info(fmt.Sprintf("Using certificate template from config. Name: %s", config.CertificateTemplate))
		template = &config.CertificateTemplate
	}

	// Populate enrollment pattern ID or name if defined
	if config.EnrollmentPatternId != 0 {
		k8sLog.Info(fmt.Sprintf("Using enrollment pattern ID from config. ID: %d", config.EnrollmentPatternId))
		enrollmentPatternId = &config.EnrollmentPatternId
	} else if config.EnrollmentPatternName != "" {
		pattern, err := getEnrollmentPatternByName(ctx, k8sLog, s, config.EnrollmentPatternName)
		if err != nil {
			return nil, nil, err
		}

		enrollmentPatternId = pattern.Id
		k8sLog.Info(fmt.Sprintf("Using enrollment pattern ID: %d", *enrollmentPatternId))
	}

	modelRequest := v1.EnrollmentCSREnrollmentRequest{
		CSR:                 string(csrBytes),
		EnrollmentPatternId: *v1.NewNullableInt32(enrollmentPatternId),
		Template:            *v1.NewNullableString(template),
		Timestamp:           ptr(time.Now()),
		IncludeChain:        ptr(true),
		SANs:                map[string][]string{},
		Metadata:            map[string]interface{}{},
	}

	if config.Meta != nil {
		modelRequest.Metadata[CommandMetaControllerNamespace] = config.Meta.ControllerNamespace
		modelRequest.Metadata[CommandMetaControllerKind] = config.Meta.ControllerKind
		modelRequest.Metadata[CommandMetaControllerResourceGroupName] = config.Meta.ControllerResourceGroupName
		modelRequest.Metadata[CommandMetaIssuerName] = config.Meta.IssuerName
		modelRequest.Metadata[CommandMetaIssuerNamespace] = config.Meta.IssuerNamespace
		modelRequest.Metadata[CommandMetaControllerReconcileId] = config.Meta.ControllerReconcileId
		modelRequest.Metadata[CommandMetaCertificateSigningRequestNamespace] = config.Meta.CertificateSigningRequestNamespace
	}

	for metaName, value := range extractMetadataFromAnnotations(config.Annotations) {
		k8sLog.Info(fmt.Sprintf("Adding metadata %q with value %q", metaName, value))
		modelRequest.Metadata[metaName] = value
	}

	var caBuilder strings.Builder
	if config.CertificateAuthorityHostname != "" {
		caBuilder.WriteString(config.CertificateAuthorityHostname)
		caBuilder.WriteString("\\")
	}
	caBuilder.WriteString(config.CertificateAuthorityLogicalName)
	modelRequest.CertificateAuthority = *v1.NewNullableString(ptr(caBuilder.String()))

	req = req.EnrollmentCSREnrollmentRequest(modelRequest)

	// Avoid nil pointer dereference in logs
	loggedEnrollmentPatternId := int32(0)
	if enrollmentPatternId != nil {
		loggedEnrollmentPatternId = *enrollmentPatternId
	}

	k8sLog.Info(fmt.Sprintf("Enrolling certificate with Command using template %q and CA %q and enrollment pattern ID %d", config.CertificateTemplate, caBuilder.String(), loggedEnrollmentPatternId))

	commandCsrResponseObject, _, err := s.client.EnrollCSR(req)
	if err != nil {
		detail := fmt.Sprintf("error enrolling certificate with Command. Verify that the certificate authority %q (%s) is configured correctly", config.CertificateAuthorityLogicalName, config.CertificateAuthorityHostname)

		if template != nil {
			detail += fmt.Sprintf(" and that the certificate template %q exists in Command", *template)
		}

		if enrollmentPatternId != nil {
			detail += fmt.Sprintf(". Make sure enrollment pattern ID %d is configured to use certificate authority %q (%s) and the security role is configured to use this enrollment pattern.", *enrollmentPatternId, config.CertificateAuthorityLogicalName, config.CertificateAuthorityHostname)
		}

		if len(extractMetadataFromAnnotations(config.Annotations)) > 0 {
			detail += ". Also verify that the metadata fields provided exist in Command"
		}

		err = fmt.Errorf("%w: %s: %w", errCommandEnrollmentFailure, detail, err)
		return nil, nil, err
	}

	var certBytes []byte
	for _, cert := range commandCsrResponseObject.CertificateInformation.Certificates {
		block, _ := pem.Decode([]byte(cert))
		if block == nil {
			return nil, nil, errors.New("failed to parse certificate PEM")
		}

		certBytes = append(certBytes, block.Bytes...)
	}

	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, nil, err
	}

	bundlePEM, err := cmpki.ParseSingleCertificateChain(certs)
	if err != nil {
		return nil, nil, err
	}
	k8sLog.Info(fmt.Sprintf("Successfully enrolled and serialized certificate with Command with subject %q. Certificate has %d SANs", certs[0].Subject, len(certs[0].DNSNames)+len(certs[0].IPAddresses)+len(certs[0].URIs)))
	return bundlePEM.ChainPEM, bundlePEM.CAPEM, nil
}

// extractMetadataFromAnnotations extracts metadata from the provided annotations
func extractMetadataFromAnnotations(annotations map[string]string) map[string]interface{} {
	metadata := make(map[string]interface{})

	for key, value := range annotations {
		if strings.HasPrefix(key, commandMetadataAnnotationPrefix) {
			metadata[strings.TrimPrefix(key, commandMetadataAnnotationPrefix)] = value
		}
	}

	return metadata
}

// parseCSR takes a byte array containing a PEM encoded CSR and returns a x509.CertificateRequest object
func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("%w: PEM block type must be CERTIFICATE REQUEST", errInvalidCSR)
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// ptr returns a pointer to the provided value
func ptr[T any](v T) *T {
	return &v
}

// getEnrollmentPatternByName retrieves an enrollment pattern by its name from Command.
func getEnrollmentPatternByName(ctx context.Context, log logr.Logger, s *signer, enrollmentPatternName string) (*v1.EnrollmentPatternsEnrollmentPatternResponse, error) {
	log.Info(fmt.Sprintf("Looking up enrollment pattern %q in Command...", enrollmentPatternName))

	var model *v1.EnrollmentPatternsEnrollmentPatternResponse

	queryString := fmt.Sprintf("Name -eq \"%s\"", enrollmentPatternName)
	patterns, httpResp, err := s.client.GetEnrollmentPatterns(v1.ApiGetEnrollmentPatternsRequest{}.QueryString(queryString))

	if err != nil {
		// Capture the error message which should indicate the failure reason
		msg := ""
		if httpResp != nil && httpResp.Body != nil {
			defer httpResp.Body.Close()
			bodyBytes, _ := io.ReadAll(httpResp.Body)
			msg += string(bodyBytes)
		}
		detail := fmt.Sprintf("error fetching enrollment patterns from Command: %s. Details: %s", err, msg)
		return nil, fmt.Errorf("%w: %s: %w", errEnrollmentPatternFailure, detail, err)
	}

	if len(patterns) == 0 {
		detail := fmt.Sprintf("enrollment pattern not found: %s", enrollmentPatternName)
		return nil, fmt.Errorf("%w: %s", errEnrollmentPatternFailure, detail)
	}

	if len(patterns) > 1 {
		detail := fmt.Sprintf("multiple enrollment patterns found: %s", enrollmentPatternName)
		return nil, fmt.Errorf("%w: %s", errEnrollmentPatternFailure, detail)
	}

	model = &patterns[0]

	log.Info(fmt.Sprintf("Enrollment pattern %s found in Command", enrollmentPatternName))

	return model, nil
}
