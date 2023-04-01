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
)

type testSigner struct {
	SignerBuilder        CommandSignerBuilder
	HealthCheckerBuilder HealthCheckerBuilder
}

func TestCommandHealthCheckerFromIssuerAndSecretData(t *testing.T) {
	obj := testSigner{
		HealthCheckerBuilder: CommandHealthCheckerFromIssuerAndSecretData,
	}

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

	certificateAuthority := os.Getenv("COMMAND_CERTIFICATE_AUTHORITY")
	if certificateAuthority == "" {
		t.Fatal("COMMAND_CERTIFICATE_AUTHORITY must be set to run this test")
	}
	spec.CertificateAuthority = certificateAuthority

	builder, err := obj.HealthCheckerBuilder(context.Background(), &spec, secretData)
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

	certificateAuthority := os.Getenv("COMMAND_CERTIFICATE_AUTHORITY")
	if certificateAuthority == "" {
		t.Fatal("COMMAND_CERTIFICATE_AUTHORITY must be set to run this test")
	}
	spec.CertificateAuthority = certificateAuthority

	builder, err := obj.SignerBuilder(context.Background(), &spec, secretData)
	if err != nil {
		t.Fatal(err)
	}

	// Generate a test CSR to sign
	csr, err := generateCSR("C=US,ST=California,L=San Francisco,O=Keyfactor,OU=Engineering,CN=example.com")
	if err != nil {
		t.Fatal(err)
	}

	signed, err := builder.Sign(context.Background(), csr)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("Signed certificate: %s", string(signed))
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
