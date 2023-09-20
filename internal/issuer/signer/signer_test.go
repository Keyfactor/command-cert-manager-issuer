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
	"os"
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
		t.Log("CA cert not found, assuming that EJBCA is using a trusted CA")
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
		return make([]byte, 0, 0), err
	}

	template := x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
	}
	var csrBuf bytes.Buffer
	csrBytes, _ := x509.CreateCertificateRequest(rand.Reader, &template, keyBytes)
	err = pem.Encode(&csrBuf, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	if err != nil {
		return make([]byte, 0, 0), err
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
				value = fmt.Sprintf("%s-%s", value, generateRandomString(5))
			} else {
				name.CommonName = value
			}
		default:
			// Ignore any unknown keys
		}
	}

	return name, nil
}
