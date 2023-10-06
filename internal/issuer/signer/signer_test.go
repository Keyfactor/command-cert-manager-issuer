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

package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	commandissuer "github.com/Keyfactor/command-issuer/api/v1alpha1"
	"github.com/Keyfactor/keyfactor-go-client-sdk/api/keyfactor"
	"github.com/stretchr/testify/assert"
	"math/big"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

type testSigner struct {
	SignerBuilder        CommandSignerBuilder
	HealthCheckerBuilder HealthCheckerBuilder
}

func TestCommandHealthCheckerFromIssuerAndSecretData(t *testing.T) {
	obj := testSigner{
		HealthCheckerBuilder: CommandHealthCheckerFromIssuerAndSecretData,
	}

	builder, err := obj.HealthCheckerBuilder(getTestHealthCheckerConfigItems(t))
	if err != nil {
		t.Fatal(err)
	}

	err = builder.Check()
	if err != nil {
		t.Fatal(err)
	}
}

func TestCommandSignerFromIssuerAndSecretData(t *testing.T) {
	t.Run("ValidSigning", func(t *testing.T) {
		obj := testSigner{
			SignerBuilder: CommandSignerFromIssuerAndSecretData,
		}

		// Generate a test CSR to sign
		csr, err := generateCSR("C=US,ST=California,L=San Francisco,O=Keyfactor,OU=Engineering,CN=example.com")
		if err != nil {
			t.Fatal(err)
		}

		meta := K8sMetadata{
			ControllerNamespace:                "test-namespace",
			ControllerKind:                     "Issuer",
			ControllerResourceGroupName:        "test-issuer.example.com",
			IssuerName:                         "test-issuer",
			IssuerNamespace:                    "test-namespace",
			ControllerReconcileId:              "GUID",
			CertificateSigningRequestNamespace: "test-namespace",
		}

		start := time.Now()
		signer, err := obj.SignerBuilder(getTestSignerConfigItems(t))
		if err != nil {
			t.Fatal(err)
		}

		signed, err := signer.Sign(context.Background(), csr, meta)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("Signing took %s", time.Since(start))

		t.Logf("Signed certificate: %s", string(signed))
	})

	// Set up test data

	spec := commandissuer.IssuerSpec{
		Hostname:                        "example-hostname.com",
		CertificateTemplate:             "example-template",
		CertificateAuthorityLogicalName: "example-logical-name",
		CertificateAuthorityHostname:    "ca-hostname.com",
		SecretName:                      "example-secret-name",
		CaSecretName:                    "example-ca-secret-name",
	}

	authSecretData := map[string][]byte{
		"username": []byte("username"),
		"password": []byte("password"),
	}

	caSecretData := map[string][]byte{
		"tls.crt": []byte("ca-cert"),
	}

	t.Run("MissingCertTemplate", func(t *testing.T) {
		templateCopy := spec.CertificateTemplate
		spec.CertificateTemplate = ""
		// Create the signer
		_, err := commandSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
		if err == nil {
			t.Errorf("expected error, got nil")
		}

		spec.CertificateTemplate = templateCopy
	})

	t.Run("MissingCaLogicalName", func(t *testing.T) {
		logicalNameCopy := spec.CertificateAuthorityLogicalName
		spec.CertificateAuthorityLogicalName = ""
		// Create the signer
		_, err := commandSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
		if err == nil {
			t.Errorf("expected error, got nil")
		}

		spec.CertificateAuthorityLogicalName = logicalNameCopy
	})

	t.Run("NoAnnotations", func(t *testing.T) {
		// Create the signer
		signer, err := commandSignerFromIssuerAndSecretData(context.Background(), &spec, make(map[string]string), authSecretData, caSecretData)
		if err != nil {
			t.Fatal(err)
		}

		// If there are no annotations, the customMetadata map should be empty
		if len(signer.customMetadata) != 0 {
			t.Errorf("expected customMetadata to be empty, got %v", signer.customMetadata)
		}
	})

	t.Run("MetadataAnnotations", func(t *testing.T) {
		annotations := map[string]string{
			commandMetadataAnnotationPrefix + "key1": "value1",
			commandMetadataAnnotationPrefix + "key2": "value2",
		}

		// Create the signer
		signer, err := commandSignerFromIssuerAndSecretData(context.Background(), &spec, annotations, authSecretData, caSecretData)
		if err != nil {
			t.Fatal(err)
		}

		// If there are no annotations, the customMetadata map should be empty
		if len(signer.customMetadata) != 2 {
			t.Errorf("expected customMetadata to have 2 entries, got %v", signer.customMetadata)
		}

		if value, ok := signer.customMetadata["key1"].(string); ok && value == "value1" {
			// They are equal
		} else {
			t.Errorf("expected customMetadata key1 to be value1, got %v", signer.customMetadata["key1"])
		}

		if value, ok := signer.customMetadata["key2"].(string); ok && value == "value2" {
			// They are equal
		} else {
			t.Errorf("expected customMetadata key1 to be value1, got %v", signer.customMetadata["key1"])
		}
	})

	t.Run("AnnotationDefaultOverrides", func(t *testing.T) {
		annotations := map[string]string{
			"command-issuer.keyfactor.com/certificateTemplate":             "TestCertificateTemplate",
			"command-issuer.keyfactor.com/certificateAuthorityLogicalName": "TestCertificateAuthorityLogicalName",
			"command-issuer.keyfactor.com/certificateAuthorityHostname":    "TestCertificateAuthorityHostname",
			"command-manager.io/certificate-name":                          "TestCertificateName",
		}

		// Create the signer
		signer, err := commandSignerFromIssuerAndSecretData(context.Background(), &spec, annotations, authSecretData, caSecretData)
		if err != nil {
			t.Fatal(err)
		}

		assert.Equal(t, "TestCertificateTemplate", signer.certificateTemplate)
		assert.Equal(t, "TestCertificateAuthorityLogicalName", signer.certificateAuthorityLogicalName)
		assert.Equal(t, "TestCertificateAuthorityHostname", signer.certificateAuthorityHostname)
		assert.Equal(t, "TestCertificateName", signer.certManagerCertificateName)
	})
}

func TestCompileCertificatesToPemBytes(t *testing.T) {
	// Generate two certificates for testing
	cert1, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate mock certificate: %v", err)
	}
	cert2, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate mock certificate: %v", err)
	}

	tests := []struct {
		name          string
		certificates  []*x509.Certificate
		expectedError bool
	}{
		{
			name:          "No certificates",
			certificates:  []*x509.Certificate{},
			expectedError: false,
		},
		{
			name:          "Single certificate",
			certificates:  []*x509.Certificate{cert1},
			expectedError: false,
		},
		{
			name:          "Multiple certificates",
			certificates:  []*x509.Certificate{cert1, cert2},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileCertificatesToPemBytes(tt.certificates)
			if (err != nil) != tt.expectedError {
				t.Errorf("expected error = %v, got %v", tt.expectedError, err)
			}
		})
	}
}

func Test_extractMetadataFromAnnotations(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		expected    map[string]interface{}
	}{
		{
			name:        "empty annotations",
			annotations: map[string]string{},
			expected:    map[string]interface{}{},
		},
		{
			name: "annotations without metadata prefix",
			annotations: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
			expected: map[string]interface{}{},
		},
		{
			name: "annotations with metadata prefix",
			annotations: map[string]string{
				commandMetadataAnnotationPrefix + "key1": "value1",
				"key2":                                   "value2",
			},
			expected: map[string]interface{}{
				"key1": "value1",
			},
		},
		{
			name: "mixed annotations",
			annotations: map[string]string{
				commandMetadataAnnotationPrefix + "key1": "value1",
				commandMetadataAnnotationPrefix + "key2": "value2",
				"key3":                                   "value3",
			},
			expected: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractMetadataFromAnnotations(tt.annotations)
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func Test_createCommandClientFromSecretData(t *testing.T) {
	cert1, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %v", err)
	}

	cert2, err := generateSelfSignedCertificate()
	if err != nil {
		t.Fatalf("failed to generate self-signed certificate: %v", err)
	}

	certBytes, err := compileCertificatesToPemBytes([]*x509.Certificate{cert1, cert2})
	if err != nil {
		return
	}

	tests := []struct {
		name           string
		spec           commandissuer.IssuerSpec
		authSecretData map[string][]byte
		caSecretData   map[string][]byte
		verify         func(*testing.T, *keyfactor.APIClient) error
		expectedErr    bool
	}{
		{
			name: "EmptySecretData",
			authSecretData: map[string][]byte{
				"username": []byte(""),
				"password": []byte(""),
			},
			verify: func(t *testing.T, client *keyfactor.APIClient) error {
				if client != nil {
					return fmt.Errorf("expected client to be nil")
				}
				return nil
			},
			expectedErr: true,
		},
		{
			name: "ValidAuthData",
			spec: commandissuer.IssuerSpec{
				Hostname: "hostname",
			},
			authSecretData: map[string][]byte{
				"username": []byte("username"),
				"password": []byte("password"),
			},
			verify: func(t *testing.T, client *keyfactor.APIClient) error {
				if client == nil {
					return fmt.Errorf("expected client to be non-nil")
				}

				if client.GetConfig().Host != "hostname" {
					return fmt.Errorf("expected hostname to be hostname, got %s", client.GetConfig().Host)
				}

				if client.GetConfig().BasicAuth.UserName != "username" {
					return fmt.Errorf("expected username to be username, got %s", client.GetConfig().BasicAuth.UserName)
				}

				if client.GetConfig().BasicAuth.Password != "password" {
					return fmt.Errorf("expected password to be password, got %s", client.GetConfig().BasicAuth.Password)
				}

				return nil
			},
			expectedErr: false,
		},
		{
			name: "InvalidCaData",
			spec: commandissuer.IssuerSpec{
				Hostname: "hostname",
			},
			authSecretData: map[string][]byte{
				"username": []byte("username"),
				"password": []byte("password"),
			},
			caSecretData: map[string][]byte{
				"tls.crt": certBytes,
			},
			verify: func(t *testing.T, client *keyfactor.APIClient) error {
				if client == nil {
					return fmt.Errorf("expected client to be non-nil")
				}

				return nil
			},
			expectedErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := createCommandClientFromSecretData(context.Background(), &tt.spec, tt.authSecretData, tt.caSecretData)
			if (err != nil) != tt.expectedErr {
				t.Errorf("expected error = %v, got %v", tt.expectedErr, err)
			}
			if err = tt.verify(t, result); err != nil {
				t.Error(err)
			}
		})
	}
}

func getTestHealthCheckerConfigItems(t *testing.T) (context.Context, *commandissuer.IssuerSpec, map[string][]byte, map[string][]byte) {
	ctx, spec, _, secret, configmap := getTestSignerConfigItems(t)
	return ctx, spec, secret, configmap
}

func getTestSignerConfigItems(t *testing.T) (context.Context, *commandissuer.IssuerSpec, map[string]string, map[string][]byte, map[string][]byte) {
	// Get the username and password from the environment
	secretData := make(map[string][]byte)
	username := os.Getenv("COMMAND_USERNAME")
	if username == "" {
		t.Fatal("COMMAND_USERNAME must be set to run this test")
	}
	secretData["username"] = []byte(username)

	password := os.Getenv("COMMAND_PASSWORD")
	if password == "" {
		t.Fatal("COMMAND_PASSWORD must be set to run this test")
	}
	secretData["password"] = []byte(password)

	// Get the hostname, certificate template, and certificate authority from the environment
	spec := commandissuer.IssuerSpec{}
	hostname := os.Getenv("COMMAND_HOSTNAME")
	if hostname == "" {
		t.Fatal("COMMAND_HOSTNAME must be set to run this test")
	}
	spec.Hostname = hostname

	certificateTemplate := os.Getenv("COMMAND_CERTIFICATE_TEMPLATE")
	if certificateTemplate == "" {
		t.Fatal("COMMAND_CERTIFICATE_TEMPLATE must be set to run this test")
	}
	spec.CertificateTemplate = certificateTemplate

	certificateAuthorityLogicalName := os.Getenv("COMMAND_CERTIFICATE_AUTHORITY_LOGICAL_NAME")
	if certificateAuthorityLogicalName == "" {
		t.Fatal("COMMAND_CERTIFICATE_AUTHORITY_LOGICAL_NAME must be set to run this test")
	}
	spec.CertificateAuthorityLogicalName = certificateAuthorityLogicalName

	certificateAuthorityHostname := os.Getenv("COMMAND_CERTIFICATE_AUTHORITY_HOSTNAME")
	if certificateAuthorityHostname == "" {
		t.Fatal("COMMAND_CERTIFICATE_AUTHORITY_HOSTNAME must be set to run this test")
	}
	spec.CertificateAuthorityHostname = certificateAuthorityHostname

	// Get the certificate authority path from the environment
	pathToCaCert := os.Getenv("COMMAND_CA_CERT_PATH")

	// Read the CA cert from the file system.
	caCertBytes, err := os.ReadFile(pathToCaCert)
	if err != nil {
		t.Log("CA cert not found, assuming that Command is using a trusted CA")
	}

	caSecretData := map[string][]byte{}
	if len(caCertBytes) != 0 {
		caSecretData["tls.crt"] = caCertBytes
	}

	return context.Background(), &spec, make(map[string]string), secretData, caSecretData
}

func generateCSR(subject string) ([]byte, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	subj, err := parseSubjectDN(subject, false)
	if err != nil {
		return make([]byte, 0), err
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	var csrBuf bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	err = pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return make([]byte, 0), err
	}

	return csrBuf.Bytes(), nil
}

// Function that turns subject string into pkix.Name
// EG "C=US,ST=California,L=San Francisco,O=HashiCorp,OU=Engineering,CN=example.com"
func parseSubjectDN(subject string, randomizeCn bool) (pkix.Name, error) {
	var name pkix.Name

	// Split the subject into its individual parts
	parts := strings.Split(subject, ",")

	for _, part := range parts {
		// Split the part into key and value
		keyValue := strings.SplitN(part, "=", 2)

		if len(keyValue) != 2 {
			return pkix.Name{}, asn1.SyntaxError{Msg: "malformed subject DN"}
		}

		key := strings.TrimSpace(keyValue[0])
		value := strings.TrimSpace(keyValue[1])

		// Map the key to the appropriate field in the pkix.Name struct
		switch key {
		case "C":
			name.Country = []string{value}
		case "ST":
			name.Province = []string{value}
		case "L":
			name.Locality = []string{value}
		case "O":
			name.Organization = []string{value}
		case "OU":
			name.OrganizationalUnit = []string{value}
		case "CN":
			if randomizeCn {
				name.CommonName = fmt.Sprintf("%s-%s", value, generateRandomString(5))
			} else {
				name.CommonName = value
			}
		default:
			// Ignore any unknown keys
		}
	}

	return name, nil
}

func generateSelfSignedCertificate() (*x509.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	return cert, nil
}
