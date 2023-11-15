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

package signer

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	commandissuer "github.com/Keyfactor/command-issuer/api/v1alpha1"
	"github.com/Keyfactor/keyfactor-go-client-sdk/api/keyfactor"
	"math/rand"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"strings"
	"time"
)

const (
	// Keyfactor enrollment PEM format
	enrollmentPEMFormat             = "PEM"
	commandMetadataAnnotationPrefix = "metadata.command-issuer.keyfactor.com/"
)

type K8sMetadata struct {
	ControllerNamespace                string
	ControllerKind                     string
	ControllerResourceGroupName        string
	IssuerName                         string
	IssuerNamespace                    string
	ControllerReconcileId              string
	CertificateSigningRequestNamespace string
}

type commandSigner struct {
	client                          *keyfactor.APIClient
	certificateTemplate             string
	certificateAuthorityLogicalName string
	certificateAuthorityHostname    string
	certManagerCertificateName      string
	customMetadata                  map[string]interface{}
}

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(context.Context, *commandissuer.IssuerSpec, map[string][]byte, map[string][]byte) (HealthChecker, error)
type CommandSignerBuilder func(context.Context, *commandissuer.IssuerSpec, map[string]string, map[string][]byte, map[string][]byte) (Signer, error)

type Signer interface {
	Sign(context.Context, []byte, K8sMetadata) ([]byte, []byte, error)
}

func CommandHealthCheckerFromIssuerAndSecretData(ctx context.Context, spec *commandissuer.IssuerSpec, authSecretData map[string][]byte, caSecretData map[string][]byte) (HealthChecker, error) {
	signer := commandSigner{}

	client, err := createCommandClientFromSecretData(ctx, spec, authSecretData, caSecretData)
	if err != nil {
		return nil, err
	}

	signer.client = client

	return &signer, nil
}

func CommandSignerFromIssuerAndSecretData(ctx context.Context, spec *commandissuer.IssuerSpec, annotations map[string]string, authSecretData map[string][]byte, caSecretData map[string][]byte) (Signer, error) {
	return commandSignerFromIssuerAndSecretData(ctx, spec, annotations, authSecretData, caSecretData)
}

func commandSignerFromIssuerAndSecretData(ctx context.Context, spec *commandissuer.IssuerSpec, annotations map[string]string, authSecretData map[string][]byte, caSecretData map[string][]byte) (*commandSigner, error) {
	k8sLog := log.FromContext(ctx)

	signer := commandSigner{}

	client, err := createCommandClientFromSecretData(ctx, spec, authSecretData, caSecretData)
	if err != nil {
		return nil, err
	}

	signer.client = client

	if spec.CertificateTemplate == "" {
		k8sLog.Error(errors.New("missing certificate template"), "missing certificate template")
		return nil, errors.New("missing certificate template")
	}
	signer.certificateTemplate = spec.CertificateTemplate

	if spec.CertificateAuthorityLogicalName == "" {
		k8sLog.Error(errors.New("missing certificate authority logical name"), "missing certificate authority logical name")
		return nil, errors.New("missing certificate authority logical name")
	}
	signer.certificateAuthorityLogicalName = spec.CertificateAuthorityLogicalName

	// CA Hostname is optional
	signer.certificateAuthorityHostname = spec.CertificateAuthorityHostname

	// Override defaults from annotations
	if value, exists := annotations["command-issuer.keyfactor.com/certificateTemplate"]; exists {
		signer.certificateTemplate = value
	}
	if value, exists := annotations["command-issuer.keyfactor.com/certificateAuthorityLogicalName"]; exists {
		signer.certificateAuthorityLogicalName = value
	}
	if value, exists := annotations["command-issuer.keyfactor.com/certificateAuthorityHostname"]; exists {
		signer.certificateAuthorityHostname = value
	}

	if value, exists := annotations["command-manager.io/certificate-name"]; exists {
		signer.certManagerCertificateName = value
	}

	k8sLog.Info(fmt.Sprintf("Using certificate template %q and certificate authority %q (%s)", signer.certificateTemplate, signer.certificateAuthorityLogicalName, signer.certificateAuthorityHostname))

	signer.customMetadata = extractMetadataFromAnnotations(annotations)

	return &signer, nil
}

func extractMetadataFromAnnotations(annotations map[string]string) map[string]interface{} {
	metadata := make(map[string]interface{})

	for key, value := range annotations {
		if strings.HasPrefix(key, commandMetadataAnnotationPrefix) {
			metadata[strings.TrimPrefix(key, commandMetadataAnnotationPrefix)] = value
		}
	}

	return metadata
}

func (s *commandSigner) Check() error {
	endpoints, _, err := s.client.StatusApi.StatusGetEndpoints(context.Background()).Execute()
	if err != nil {
		detail := "failed to get endpoints from Keyfactor Command"

		var bodyError *keyfactor.GenericOpenAPIError
		ok := errors.As(err, &bodyError)
		if ok {
			detail += fmt.Sprintf(" - %s", string(bodyError.Body()))
		}

		detail += fmt.Sprintf(" (%s)", err.Error())

		return errors.New(detail)
	}

	for _, endpoint := range endpoints {
		if strings.Contains(endpoint, "POST /Enrollment/CSR") {
			return nil
		}
	}

	return errors.New("missing \"POST /Enrollment/CSR\" endpoint")
}

func (s *commandSigner) Sign(ctx context.Context, csrBytes []byte, k8sMeta K8sMetadata) ([]byte, []byte, error) {
	k8sLog := log.FromContext(ctx)

	csr, err := parseCSR(csrBytes)
	if err != nil {
		k8sLog.Error(err, "failed to parse CSR")
		return nil, nil, err
	}

	// Log the common metadata of the CSR
	k8sLog.Info(fmt.Sprintf("Found CSR wtih Common Name %q and %d DNS SANs, %d IP SANs, and %d URI SANs", csr.Subject.CommonName, len(csr.DNSNames), len(csr.IPAddresses), len(csr.URIs)))

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

	modelRequest := keyfactor.ModelsEnrollmentCSREnrollmentRequest{
		CSR:          string(csrBytes),
		IncludeChain: ptr(true),
		Metadata: map[string]interface{}{
			CommandMetaControllerNamespace:                k8sMeta.ControllerNamespace,
			CommandMetaControllerKind:                     k8sMeta.ControllerKind,
			CommandMetaControllerResourceGroupName:        k8sMeta.ControllerResourceGroupName,
			CommandMetaIssuerName:                         k8sMeta.IssuerName,
			CommandMetaIssuerNamespace:                    k8sMeta.IssuerNamespace,
			CommandMetaControllerReconcileId:              k8sMeta.ControllerReconcileId,
			CommandMetaCertificateSigningRequestNamespace: k8sMeta.CertificateSigningRequestNamespace,
		},
		Template: &s.certificateTemplate,
		SANs:     nil,
	}

	for metaName, value := range s.customMetadata {
		k8sLog.Info(fmt.Sprintf("Adding metadata %q with value %q", metaName, value))
		modelRequest.Metadata[metaName] = value
	}

	var caBuilder strings.Builder
	if s.certificateAuthorityHostname != "" {
		caBuilder.WriteString(s.certificateAuthorityHostname)
		caBuilder.WriteString("\\")
	}
	caBuilder.WriteString(s.certificateAuthorityLogicalName)

	modelRequest.SetCertificateAuthority(caBuilder.String())
	modelRequest.SetTimestamp(time.Now())

	commandCsrResponseObject, _, err := s.client.EnrollmentApi.EnrollmentPostCSREnroll(context.Background()).Request(modelRequest).XCertificateformat(enrollmentPEMFormat).Execute()
	if err != nil {
		detail := fmt.Sprintf("error enrolling certificate with Command. Verify that the certificate template %q exists and that the certificate authority %q (%s) is configured correctly.", s.certificateTemplate, s.certificateAuthorityLogicalName, s.certificateAuthorityHostname)

		if len(s.customMetadata) > 0 {
			detail += " Also verify that the metadata fields provided exist in Command."
		}

		var bodyError *keyfactor.GenericOpenAPIError
		ok := errors.As(err, &bodyError)
		if ok {
			detail += fmt.Sprintf(" - %s", string(bodyError.Body()))
		}

		k8sLog.Error(err, detail)

		return nil, nil, fmt.Errorf(detail)
	}

	certAndChain, err := getCertificatesFromCertificateInformation(commandCsrResponseObject.CertificateInformation)
	if err != nil {
		return nil, nil, err
	}

	k8sLog.Info(fmt.Sprintf("Successfully enrolled certificate with Command with subject %q. Certificate has %d SANs", certAndChain[0].Subject, len(certAndChain[0].DNSNames)+len(certAndChain[0].IPAddresses)+len(certAndChain[0].URIs)))

	// Return the certificate and chain in PEM format
	return compileCertificatesToPemBytes(certAndChain)
}

func getCertificatesFromCertificateInformation(commandResp *keyfactor.ModelsPkcs10CertificateResponse) ([]*x509.Certificate, error) {
	var certBytes []byte

	for _, cert := range commandResp.Certificates {
		block, _ := pem.Decode([]byte(cert))
		if block == nil {
			return nil, errors.New("failed to parse certificate PEM")
		}

		certBytes = append(certBytes, block.Bytes...)
	}

	certs, err := x509.ParseCertificates(certBytes)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

// compileCertificatesToPemString takes a slice of x509 certificates and returns a string containing the certificates in PEM format
// If an error occurred, the function logs the error and continues to parse the remaining objects.
func compileCertificatesToPemBytes(certificates []*x509.Certificate) ([]byte, []byte, error) {
	var leaf strings.Builder
	var chain strings.Builder

	for i, certificate := range certificates {
		if i == 0 {
			err := pem.Encode(&leaf, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certificate.Raw,
			})
			if err != nil {
				return make([]byte, 0), make([]byte, 0), err
			}
		} else {
			err := pem.Encode(&chain, &pem.Block{
				Type:  "CERTIFICATE",
				Bytes: certificate.Raw,
			})
			if err != nil {
				return make([]byte, 0), make([]byte, 0), err
			}
		}
	}

	return []byte(leaf.String()), []byte(chain.String()), nil
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

func createCommandClientFromSecretData(ctx context.Context, spec *commandissuer.IssuerSpec, authSecretData map[string][]byte, caSecretData map[string][]byte) (*keyfactor.APIClient, error) {
	k8sLogger := log.FromContext(ctx)

	// Get username and password from secretData which contains key value pairs of a kubernetes.io/basic-auth secret
	username := string(authSecretData["username"])
	if username == "" {
		k8sLogger.Error(errors.New("missing username"), "missing username")
		return nil, errors.New("missing username")
	}
	password := string(authSecretData["password"])
	if password == "" {
		k8sLogger.Error(errors.New("missing password"), "missing password")
		return nil, errors.New("missing password")
	}

	keyfactorConfig := make(map[string]string)

	// Set username and password for the Keyfactor client
	for key, value := range authSecretData {
		keyfactorConfig[key] = string(value)
	}
	// Set the hostname for the Keyfactor client
	keyfactorConfig["host"] = spec.Hostname

	config := keyfactor.NewConfiguration(keyfactorConfig)
	if config == nil {
		k8sLogger.Error(errors.New("failed to create Keyfactor configuration"), "failed to create Keyfactor configuration")
		return nil, errors.New("failed to create Keyfactor configuration")
	}

	// Set the user agent for the Keyfactor client
	config.UserAgent = "command-issuer"

	// If the CA certificate is provided, add it to the EJBCA configuration
	if len(caSecretData) > 0 {
		// There is no requirement that the CA certificate is stored under a specific key in the secret, so we can just iterate over the map
		var caCertBytes []byte
		for _, caCertBytes = range caSecretData {
		}

		// Try to decode caCertBytes as a PEM formatted block
		caChainBlocks, _ := decodePEMBytes(caCertBytes)
		if caChainBlocks != nil {
			var caChain []*x509.Certificate
			for _, block := range caChainBlocks {
				// Parse the PEM block into an x509 certificate
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, err
				}

				caChain = append(caChain, cert)
			}

			config.SetCaCertificates(caChain)
		}
	}

	client := keyfactor.NewAPIClient(config)
	if client == nil {
		k8sLogger.Error(errors.New("failed to create Keyfactor client"), "failed to create Keyfactor client")
		return nil, errors.New("failed to create Keyfactor client")
	}

	k8sLogger.Info("Created Keyfactor Command client")

	return client, nil
}

func decodePEMBytes(buf []byte) ([]*pem.Block, *pem.Block) {
	var privKey *pem.Block
	var certificates []*pem.Block
	var block *pem.Block
	for {
		block, buf = pem.Decode(buf)
		if block == nil {
			break
		} else if strings.Contains(block.Type, "PRIVATE KEY") {
			privKey = block
		} else {
			certificates = append(certificates, block)
		}
	}
	return certificates, privKey
}

func parseCSR(pemBytes []byte) (*x509.CertificateRequest, error) {
	// extract PEM from request object
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("PEM block type must be CERTIFICATE REQUEST")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

func generateRandomString(length int) string {
	rand.Seed(time.Now().UnixNano())
	letters := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	b := make([]rune, length)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

func ptr[T any](v T) *T {
	return &v
}
