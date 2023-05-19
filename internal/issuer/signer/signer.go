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
	enrollmentPEMFormat = "PEM"
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
}

type HealthChecker interface {
	Check() error
}

type HealthCheckerBuilder func(context.Context, *commandissuer.IssuerSpec, map[string][]byte) (HealthChecker, error)

type Signer interface {
	Sign(context.Context, []byte, K8sMetadata) ([]byte, error)
}

type CommandSignerBuilder func(context.Context, *commandissuer.IssuerSpec, map[string][]byte) (Signer, error)

func CommandHealthCheckerFromIssuerAndSecretData(ctx context.Context, spec *commandissuer.IssuerSpec, secretData map[string][]byte) (HealthChecker, error) {
	signer := commandSigner{}

	client, err := createCommandClientFromSecretData(ctx, spec, secretData)
	if err != nil {
		return nil, err
	}

	signer.client = client

	return &signer, nil
}

func CommandSignerFromIssuerAndSecretData(ctx context.Context, spec *commandissuer.IssuerSpec, secretData map[string][]byte) (Signer, error) {
	k8sLog := log.FromContext(ctx)

	signer := commandSigner{}

	client, err := createCommandClientFromSecretData(ctx, spec, secretData)
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

	k8sLog.Info(fmt.Sprintf("Using certificate template \"%s\" and certificate authority \"%s\" (%s)", signer.certificateTemplate, signer.certificateAuthorityLogicalName, signer.certificateAuthorityHostname))

	return &signer, nil
}

func (s *commandSigner) Check() error {
	endpoints, _, err := s.client.StatusApi.StatusGetEndpoints(context.Background()).Execute()
	if err != nil {
		detail := fmt.Sprintf("failed to get endpoints from Keyfactor Command")

		bodyError, ok := err.(*keyfactor.GenericOpenAPIError)
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

func (s *commandSigner) Sign(ctx context.Context, csrBytes []byte, k8sMeta K8sMetadata) ([]byte, error) {
	k8sLog := log.FromContext(ctx)

	csr, err := parseCSR(csrBytes)
	if err != nil {
		k8sLog.Error(err, "failed to parse CSR")
		return nil, err
	}

	// Log the common metadata of the CSR
	k8sLog.Info(fmt.Sprintf("Found CSR wtih Common Name \"%s\" and %d DNS SANs, %d IP SANs, and %d URI SANs", csr.Subject.CommonName, len(csr.DNSNames), len(csr.IPAddresses), len(csr.URIs)))

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
		SANs:     nil, // TODO figure out if the SANs from csr need to be copied here
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
		detail := fmt.Sprintf("error enrolling certificate with Command. verify that the certificate template \"%s\" exists and that the certificate authority \"%s\" (%s) is configured correctly", s.certificateTemplate, s.certificateAuthorityLogicalName, s.certificateAuthorityHostname)

		bodyError, ok := err.(*keyfactor.GenericOpenAPIError)
		if ok {
			detail += fmt.Sprintf(" - %s", string(bodyError.Body()))
		}

		k8sLog.Error(err, detail)

		return nil, fmt.Errorf(detail)
	}

	certAndChain, err := getCertificatesFromCertificateInformation(commandCsrResponseObject.CertificateInformation)
	if err != nil {
		return nil, err
	}

	k8sLog.Info(fmt.Sprintf("Successfully enrolled certificate with Command with subject \"%s\". Certificate has %d SANs", certAndChain[0].Subject, len(certAndChain[0].DNSNames)+len(certAndChain[0].IPAddresses)+len(certAndChain[0].URIs)))

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
func compileCertificatesToPemBytes(certificates []*x509.Certificate) ([]byte, error) {
	var pemBuilder strings.Builder

	for _, certificate := range certificates {
		err := pem.Encode(&pemBuilder, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certificate.Raw,
		})
		if err != nil {
			return make([]byte, 0, 0), err
		}
	}

	return []byte(pemBuilder.String()), nil
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

var (
	// Map used to determine if Keyfactor Command has a metadata field with a given name in O(1) time.
	commandMetadataMap = map[string]string{
		CommandMetaControllerNamespace:                "The namespace that the controller container is running in.",
		CommandMetaControllerKind:                     "The type of issuer that the controller used to issue this certificate.",
		CommandMetaControllerResourceGroupName:        "The group name of the resource that the Issuer or ClusterIssuer controller is managing.",
		CommandMetaIssuerName:                         "The name of the K8s issuer resource",
		CommandMetaIssuerNamespace:                    "The namespace that the issuer resource was created in.",
		CommandMetaControllerReconcileId:              "The certificate reconcile ID that the controller used to issue this certificate.",
		CommandMetaCertificateSigningRequestNamespace: "The namespace that the CertificateSigningRequest resource was created in.",
	}
)

func createCommandClientFromSecretData(ctx context.Context, spec *commandissuer.IssuerSpec, secretData map[string][]byte) (*keyfactor.APIClient, error) {
	k8sLogger := log.FromContext(ctx)

	// Get username and password from secretData which contains key value pairs of a kubernetes.io/basic-auth secret
	username := string(secretData["username"])
	if username == "" {
		k8sLogger.Error(errors.New("missing username"), "missing username")
		return nil, errors.New("missing username")
	}
	password := string(secretData["password"])
	if password == "" {
		k8sLogger.Error(errors.New("missing password"), "missing password")
		return nil, errors.New("missing password")
	}

	config := keyfactor.NewConfiguration()
	if spec.Hostname != "" {
		config.Host = spec.Hostname
	} else {
		k8sLogger.Error(errors.New("missing hostname"), "missing hostname")
		return nil, errors.New("missing hostname")
	}

	// Set username and password for the Keyfactor client
	config.BasicAuth.UserName = username
	config.BasicAuth.Password = password

	// Set the user agent for the Keyfactor client
	config.UserAgent = "command-issuer"

	client := keyfactor.NewAPIClient(config)
	if client == nil {
		k8sLogger.Error(errors.New("failed to create Keyfactor client"), "failed to create Keyfactor client")
		return nil, errors.New("failed to create Keyfactor client")
	}

	k8sLogger.Info("Created Keyfactor Command client")

	return client, nil
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
