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

package command

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	commandsdk "github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBasicAuthValidate(t *testing.T) {
	tests := []struct {
		name      string
		basicAuth *BasicAuth
		wantErr   string
	}{
		{
			name:      "nil BasicAuth",
			basicAuth: nil,
			wantErr:   "",
		},
		{
			name:      "empty Username",
			basicAuth: &BasicAuth{Username: "", Password: "pass"},
			wantErr:   "invalid config: username is required",
		},
		{
			name:      "empty Password",
			basicAuth: &BasicAuth{Username: "user", Password: ""},
			wantErr:   "invalid config: password is required",
		},
		{
			name:      "valid BasicAuth",
			basicAuth: &BasicAuth{Username: "user", Password: "pass"},
			wantErr:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.basicAuth.validate()
			if tt.wantErr == "" && err != nil {
				t.Errorf("expected no error, got %v", err)
			} else if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}

func TestOAuthValidate(t *testing.T) {
	tests := []struct {
		name    string
		oauth   *OAuth
		wantErr string
	}{
		{
			name:    "nil OAuth",
			oauth:   nil,
			wantErr: "",
		},
		{
			name:    "empty TokenURL",
			oauth:   &OAuth{TokenURL: "", ClientID: "id", ClientSecret: "secret"},
			wantErr: "invalid config: tokenURL is required",
		},
		{
			name:    "empty ClientID",
			oauth:   &OAuth{TokenURL: "http://token.url", ClientID: "", ClientSecret: "secret"},
			wantErr: "invalid config: clientID is required",
		},
		{
			name:    "empty ClientSecret",
			oauth:   &OAuth{TokenURL: "http://token.url", ClientID: "id", ClientSecret: ""},
			wantErr: "invalid config: clientSecret is required",
		},
		{
			name:    "valid OAuth",
			oauth:   &OAuth{TokenURL: "http://token.url", ClientID: "id", ClientSecret: "secret", Scopes: []string{"scope"}},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.oauth.validate()
			if tt.wantErr == "" && err != nil {
				t.Errorf("expected no error, got %v", err)
			} else if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr string
	}{
		{
			name:    "missing Hostname",
			config:  &Config{Hostname: "", APIPath: "/api"},
			wantErr: "invalid config: hostname is required",
		},
		{
			name:    "missing APIPath",
			config:  &Config{Hostname: "example.com", APIPath: ""},
			wantErr: "invalid config: apiPath is required",
		},
		{
			name:    "invalid BasicAuth",
			config:  &Config{Hostname: "example.com", APIPath: "/api", BasicAuth: &BasicAuth{Username: "", Password: "pass"}},
			wantErr: "invalid config: username is required",
		},
		{
			name:    "invalid OAuth",
			config:  &Config{Hostname: "example.com", APIPath: "/api", OAuth: &OAuth{TokenURL: "", ClientID: "id", ClientSecret: "secret"}},
			wantErr: "invalid config: tokenURL is required",
		},
		{
			name:    "all valid with no auth",
			config:  &Config{Hostname: "example.com", APIPath: "/api"},
			wantErr: "",
		},
		{
			name:    "all valid with BasicAuth",
			config:  &Config{Hostname: "example.com", APIPath: "/api", BasicAuth: &BasicAuth{Username: "user", Password: "pass"}},
			wantErr: "",
		},
		{
			name:    "all valid with OAuth",
			config:  &Config{Hostname: "example.com", APIPath: "/api", OAuth: &OAuth{TokenURL: "http://token.url", ClientID: "id", ClientSecret: "secret"}},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr == "" && err != nil {
				t.Errorf("expected no error, got %v", err)
			} else if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}

func TestSignConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *SignConfig
		wantErr string
	}{
		{
			name:    "missing certificateTemplate",
			config:  &SignConfig{CertificateTemplate: "", CertificateAuthorityLogicalName: "ca-logical", CertificateAuthorityHostname: "ca.example.com"},
			wantErr: "certificateTemplate is required",
		},
		{
			name:    "missing certificateAuthorityLogicalName",
			config:  &SignConfig{CertificateTemplate: "myTemplate", CertificateAuthorityLogicalName: "", CertificateAuthorityHostname: "ca.example.com"},
			wantErr: "certificateAuthorityLogicalName is required",
		},
		{
			name:    "missing certificateAuthorityHostname",
			config:  &SignConfig{CertificateTemplate: "myTemplate", CertificateAuthorityLogicalName: "ca-logical", CertificateAuthorityHostname: ""},
			wantErr: "certificateAuthorityHostname is required",
		},
		{
			name:    "all valid fields",
			config:  &SignConfig{CertificateTemplate: "myTemplate", CertificateAuthorityLogicalName: "ca-logical", CertificateAuthorityHostname: "ca.example.com"},
			wantErr: "",
		},
		{
			name: "valid with optional fields",
			config: &SignConfig{
				CertificateTemplate:             "myTemplate",
				CertificateAuthorityLogicalName: "ca-logical",
				CertificateAuthorityHostname:    "ca.example.com",
				Annotations:                     map[string]string{"environment": "prod"},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.validate()
			if tt.wantErr == "" && err != nil {
				t.Errorf("expected no error, got %v", err)
			} else if tt.wantErr != "" {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.wantErr)
				} else if err.Error() != tt.wantErr {
					t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
				}
			}
		})
	}
}

var (
	_ commandsdk.AuthConfig = &fakeCommandAuthenticator{}
)

type fakeCommandAuthenticator struct {
	client *http.Client
	config *auth_providers.Server
}

// Authenticate implements api.AuthConfig.
func (f *fakeCommandAuthenticator) Authenticate() error {
	return nil
}

// GetHttpClient implements api.AuthConfig.
func (f *fakeCommandAuthenticator) GetHttpClient() (*http.Client, error) {
	return f.client, nil
}

// GetServerConfig implements api.AuthConfig.
func (f *fakeCommandAuthenticator) GetServerConfig() *auth_providers.Server {
	return f.config
}

func newFakeCommandClientFunc(httpClient *http.Client) newCommandClientFunc {
	return newCommandClientFunc(func(s *auth_providers.Server, ctx *context.Context) (*commandsdk.Client, error) {
		client := &commandsdk.Client{
			AuthClient: &fakeCommandAuthenticator{
				client: httpClient,
				config: s,
			},
		}

		return client, nil
	})
}

func TestNewServerConfig(t *testing.T) {

	testCases := map[string]struct {
		config *Config

		expectedAuthProviderServer *auth_providers.Server
		expectedError              error
	}{
		"no-config": {
			config: nil,

			expectedError:              errInvalidConfig,
			expectedAuthProviderServer: nil,
		},
		"basic-auth": {
			config: &Config{
				Hostname: "example.com",
				APIPath:  "///api//", // should remove preceding & trailing slashes
				BasicAuth: &BasicAuth{
					Username: "domain\\username",
					Password: "password",
				},
			},

			expectedAuthProviderServer: &auth_providers.Server{
				Host:          "example.com",
				Username:      "domain\\username",
				Password:      "password",
				Domain:        "",
				ClientID:      "",
				ClientSecret:  "",
				OAuthTokenUrl: "",
				APIPath:       "api",
				Audience:      "",
				SkipTLSVerify: false,
				AuthType:      "basic",
			},
			expectedError: nil,
		},
		"oauth": {
			config: &Config{
				Hostname: "example.com",
				APIPath:  "///api//", // should remove preceding & trailing slashes
				OAuth: &OAuth{
					TokenURL:     "http://token.url",
					ClientID:     "id",
					ClientSecret: "secret",
					Scopes:       []string{"cert:issuer"},
					Audience:     "example.com",
				},
			},

			expectedAuthProviderServer: &auth_providers.Server{
				Host:          "example.com",
				ClientID:      "id",
				ClientSecret:  "secret",
				AccessToken:   "",
				OAuthTokenUrl: "http://token.url",
				APIPath:       "api",
				Scopes:        []string{"cert:issuer"},
				Audience:      "example.com",
				SkipTLSVerify: false,
				AuthType:      "oauth",
			},
			expectedError: nil,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			serverConfig, err := newServerConfig(context.Background(), tc.config)
			if tc.expectedError != nil {
				assertErrorIs(t, tc.expectedError, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, *tc.expectedAuthProviderServer, *serverConfig)
			}
		})
	}
}

var (
	_ Client = &fakeClient{}
)

type fakeClient struct {
	enrollCallback func(*commandsdk.EnrollCSRFctArgs)
	enrollResponse *commandsdk.EnrollResponse

	metadataFields []commandsdk.MetadataField

	err error
}

// EnrollCSR implements Client.
func (f *fakeClient) EnrollCSR(ea *commandsdk.EnrollCSRFctArgs) (*commandsdk.EnrollResponse, error) {
	if f.enrollCallback != nil {
		f.enrollCallback(ea)
	}
	return f.enrollResponse, f.err
}

// GetAllMetadataFields implements Client.
func (f *fakeClient) GetAllMetadataFields() ([]commandsdk.MetadataField, error) {
	return f.metadataFields, f.err
}

// TestConnection implements Client.
func (f *fakeClient) TestConnection() error {
	return f.err
}

func TestSign(t *testing.T) {
	caCert, rootKey := issueTestCertificate(t, "Root-CA", nil, nil)
	caCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw})

	issuingCert, issuingKey := issueTestCertificate(t, "Sub-CA", caCert, rootKey)
	issuingCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: issuingCert.Raw})

	leafCert, _ := issueTestCertificate(t, "LeafCert", issuingCert, issuingKey)
	leafCertPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafCert.Raw})

	expectedLeafAndChain := append([]*x509.Certificate{leafCert}, issuingCert)

	certificateTemplateName := "fake-cert-template"
	certificateAuthorityLogicalName := "fake-issuing-ca"
	certificateAuthorityHostname := "pki.example.com"

	testCases := map[string]struct {
		enrollCSRFunctionError error

		// Request
		config *SignConfig

		// Expected
		expectedEnrollArgs *commandsdk.EnrollCSRFctArgs
		expectedSignError  error
	}{
		"success-no-meta": {
			// Request
			config: &SignConfig{
				CertificateTemplate:             certificateTemplateName,
				CertificateAuthorityLogicalName: certificateAuthorityLogicalName,
				CertificateAuthorityHostname:    certificateAuthorityHostname,
				Meta:                            nil,
				Annotations:                     nil,
			},

			// Expected
			expectedEnrollArgs: &commandsdk.EnrollCSRFctArgs{
				Template:             certificateTemplateName,
				CertificateAuthority: fmt.Sprintf("%s\\%s", certificateAuthorityHostname, certificateAuthorityLogicalName),
				SANs:                 &commandsdk.SANs{},
				Metadata:             map[string]interface{}{},
			},
			expectedSignError: nil,
		},
		"success-annotation-config-override": {
			// Request
			config: &SignConfig{
				CertificateTemplate:             certificateTemplateName,
				CertificateAuthorityLogicalName: certificateAuthorityLogicalName,
				CertificateAuthorityHostname:    certificateAuthorityHostname,
				Meta:                            nil,
				Annotations: map[string]string{
					"command-issuer.keyfactor.com/certificateTemplate":             "template-override",
					"command-issuer.keyfactor.com/certificateAuthorityLogicalName": "logicalname-override",
					"command-issuer.keyfactor.com/certificateAuthorityHostname":    "hostname-override",
				},
			},

			// Expected
			expectedEnrollArgs: &commandsdk.EnrollCSRFctArgs{
				Template:             "template-override",
				CertificateAuthority: fmt.Sprintf("%s\\%s", "hostname-override", "logicalname-override"),
				SANs:                 &commandsdk.SANs{},
				Metadata:             map[string]interface{}{},
			},
			expectedSignError: nil,
		},
		"success-predefined-meta": {
			// Request
			config: &SignConfig{
				CertificateTemplate:             certificateTemplateName,
				CertificateAuthorityLogicalName: certificateAuthorityLogicalName,
				CertificateAuthorityHostname:    certificateAuthorityHostname,
				Meta: &K8sMetadata{
					ControllerNamespace:                "namespace",
					ControllerKind:                     "Issuer",
					ControllerResourceGroupName:        "rg.test.com",
					IssuerName:                         "test",
					IssuerNamespace:                    "ns",
					ControllerReconcileId:              "alksdfjlasdljkf",
					CertificateSigningRequestNamespace: "other-namespace",
					CertManagerCertificateName:         "cert-name",
				},
				Annotations: nil,
			},

			// Expected
			expectedEnrollArgs: &commandsdk.EnrollCSRFctArgs{
				Template:             certificateTemplateName,
				CertificateAuthority: fmt.Sprintf("%s\\%s", certificateAuthorityHostname, certificateAuthorityLogicalName),
				SANs:                 &commandsdk.SANs{},
				Metadata: map[string]interface{}{
					CommandMetaControllerNamespace:                "namespace",
					CommandMetaControllerKind:                     "Issuer",
					CommandMetaControllerResourceGroupName:        "rg.test.com",
					CommandMetaIssuerName:                         "test",
					CommandMetaIssuerNamespace:                    "ns",
					CommandMetaControllerReconcileId:              "alksdfjlasdljkf",
					CommandMetaCertificateSigningRequestNamespace: "other-namespace",
				},
			},
			expectedSignError: nil,
		},
		"success-custom-meta": {
			// Request
			config: &SignConfig{
				CertificateTemplate:             certificateTemplateName,
				CertificateAuthorityLogicalName: certificateAuthorityLogicalName,
				CertificateAuthorityHostname:    certificateAuthorityHostname,
				Meta:                            nil,
				Annotations: map[string]string{
					fmt.Sprintf("%s%s", commandMetadataAnnotationPrefix, "testMetadata"): "test",
				},
			},

			// Expected
			expectedEnrollArgs: &commandsdk.EnrollCSRFctArgs{
				Template:             certificateTemplateName,
				CertificateAuthority: fmt.Sprintf("%s\\%s", certificateAuthorityHostname, certificateAuthorityLogicalName),
				SANs:                 &commandsdk.SANs{},
				Metadata: map[string]interface{}{
					"testMetadata": "test",
				},
			},
			expectedSignError: nil,
		},
		"enroll-csr-err": {
			enrollCSRFunctionError: errors.New("an error from Command"),
			// Request
			config: &SignConfig{
				CertificateTemplate:             certificateTemplateName,
				CertificateAuthorityLogicalName: certificateAuthorityLogicalName,
				CertificateAuthorityHostname:    certificateAuthorityHostname,
				Meta:                            nil,
				Annotations:                     nil,
			},

			// Expected
			expectedEnrollArgs: &commandsdk.EnrollCSRFctArgs{
				Template:             certificateTemplateName,
				CertificateAuthority: fmt.Sprintf("%s\\%s", certificateAuthorityHostname, certificateAuthorityLogicalName),
				SANs:                 &commandsdk.SANs{},
				Metadata:             map[string]interface{}{},
			},
			expectedSignError: errCommandEnrollmentFailure,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			cb := func(ea *commandsdk.EnrollCSRFctArgs) {
				require.Equal(t, tc.expectedEnrollArgs.CertificateAuthority, ea.CertificateAuthority)
				require.Equal(t, tc.expectedEnrollArgs.Template, ea.Template)

				require.Equal(t, tc.expectedEnrollArgs.Metadata, ea.Metadata)
			}

			client := fakeClient{
				err: tc.enrollCSRFunctionError,

				enrollResponse: certificateRestResponseFromExpectedCerts(t, expectedLeafAndChain, []*x509.Certificate{caCert}),
				enrollCallback: cb,
			}
			signer := signer{
				client: &client,
			}

			csrBytes, err := generateCSR("CN=command.example.org", nil, nil, nil)
			require.NoError(t, err)
			csrPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes.Raw})

			leafAndCA, root, err := signer.Sign(context.Background(), csrPem, tc.config)
			if tc.expectedSignError != nil {
				assertErrorIs(t, tc.expectedSignError, err)
			} else {
				assert.NoError(t, err)

				require.Equal(t, leafAndCA, append(leafCertPem, issuingCertPem...))
				require.Equal(t, root, caCertPem)
			}
		})
	}
}

func TestCommandSupportsMetadata(t *testing.T) {
	testCases := map[string]struct {
		presentMeta []commandsdk.MetadataField

		// Expected
		expected bool
	}{
		"success-no-meta": {
			presentMeta: []commandsdk.MetadataField{},

			// Expected
			expected: false,
		},
		"success-all-meta": {
			presentMeta: []commandsdk.MetadataField{
				{
					Name: CommandMetaControllerNamespace,
				},
				{
					Name: CommandMetaControllerKind,
				},
				{
					Name: CommandMetaControllerResourceGroupName,
				},
				{
					Name: CommandMetaIssuerName,
				},
				{
					Name: CommandMetaIssuerNamespace,
				},
				{
					Name: CommandMetaControllerReconcileId,
				},
				{
					Name: CommandMetaCertificateSigningRequestNamespace,
				},
			},

			// Expected
			expected: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			client := fakeClient{
				err: nil,

				metadataFields: tc.presentMeta,
			}
			signer := signer{
				client: &client,
			}

			supported, err := signer.CommandSupportsMetadata()
			assert.NoError(t, err)
			require.Equal(t, tc.expected, supported)
		})
	}
}

func assertErrorIs(t *testing.T, expectedError, actualError error) {
	if !assert.Error(t, actualError) {
		return
	}
	assert.Truef(t, errors.Is(actualError, expectedError), "unexpected error type. expected: %v, got: %v", expectedError, actualError)
}

func certificateRestResponseFromExpectedCerts(t *testing.T, leafCertAndChain []*x509.Certificate, rootCAs []*x509.Certificate) *commandsdk.EnrollResponse {
	require.NotEqual(t, 0, len(leafCertAndChain))
	leaf := string(pem.EncodeToMemory(&pem.Block{Bytes: leafCertAndChain[0].Raw, Type: "CERTIFICATE"}))

	certs := []string{leaf}
	for _, cert := range leafCertAndChain[1:] {
		certs = append(certs, string(pem.EncodeToMemory(&pem.Block{Bytes: cert.Raw, Type: "CERTIFICATE"})))
	}
	for _, cert := range rootCAs {
		certs = append(certs, string(pem.EncodeToMemory(&pem.Block{Bytes: cert.Raw, Type: "CERTIFICATE"})))
	}

	response := &commandsdk.EnrollResponse{
		Certificates: certs,
		CertificateInformation: commandsdk.CertificateInformation{
			SerialNumber:       "",
			IssuerDN:           "",
			Thumbprint:         "",
			KeyfactorID:        0,
			KeyfactorRequestID: 0,
			PKCS12Blob:         "",
			Certificates:       certs,
			RequestDisposition: "",
			DispositionMessage: "",
			EnrollmentContext:  nil,
		},
	}
	return response
}

func generateCSR(subject string, dnsNames []string, uris []string, ipAddresses []string) (*x509.CertificateRequest, error) {
	keyBytes, _ := rsa.GenerateKey(rand.Reader, 2048)

	var name pkix.Name

	if subject != "" {
		// Split the subject into its individual parts
		parts := strings.Split(subject, ",")

		for _, part := range parts {
			// Split the part into key and value
			keyValue := strings.SplitN(part, "=", 2)

			if len(keyValue) != 2 {
				return nil, errors.New("invalid subject")
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
				name.CommonName = value
			default:
				// Ignore any unknown keys
			}
		}
	}

	template := x509.CertificateRequest{
		Subject:            name,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	if len(dnsNames) > 0 {
		template.DNSNames = dnsNames
	}

	// Parse and add URIs
	var uriPointers []*url.URL
	for _, u := range uris {
		if u == "" {
			continue
		}
		uriPointer, err := url.Parse(u)
		if err != nil {
			return nil, err
		}
		uriPointers = append(uriPointers, uriPointer)
	}
	template.URIs = uriPointers

	// Parse and add IPAddresses
	var ipAddrs []net.IP
	for _, ipStr := range ipAddresses {
		if ipStr == "" {
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipAddrs = append(ipAddrs, ip)
	}
	template.IPAddresses = ipAddrs

	// Generate the CSR
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	if err != nil {
		return nil, err
	}

	parsedCSR, err := x509.ParseCertificateRequest(csrBytes)
	if err != nil {
		return nil, err
	}

	return parsedCSR, nil
}

func issueTestCertificate(t *testing.T, cn string, parent *x509.Certificate, signingKey any) (*x509.Certificate, *ecdsa.PrivateKey) {
	var err error
	var key *ecdsa.PrivateKey
	now := time.Now()

	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	publicKey := &key.PublicKey
	signerPrivateKey := key
	if signingKey != nil {
		signerPrivateKey = signingKey.(*ecdsa.PrivateKey)
	}

	serial, _ := rand.Int(rand.Reader, big.NewInt(1337))
	certTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: cn},
		SerialNumber:          serial,
		BasicConstraintsValid: true,
		IsCA:                  true,
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour * 24),
	}

	if parent == nil {
		parent = certTemplate
	}

	certData, err := x509.CreateCertificate(rand.Reader, certTemplate, parent, publicKey, signerPrivateKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certData)
	require.NoError(t, err)

	return cert, key
}
