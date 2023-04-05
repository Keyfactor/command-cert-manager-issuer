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

	builder, err := obj.HealthCheckerBuilder(getTestSignerConfigItems(t))
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

func TestCommandSigner_setupCommandK8sMetadata(t *testing.T) {
	deleteBeforeCheck := false
	client, err := createCommandClientFromSecretData(getTestSignerConfigItems(t))
	if err != nil {
		t.Fatal(err)
	}

	signer := commandSigner{
		client: client,
	}

	if deleteBeforeCheck {
		err = deleteCommandK8sMetadataItems(t, client)
		if err != nil {
			t.Fatal(err)
		}

		// Log the time required to setup the metadata
		start := time.Now()
		err = signer.setupCommandK8sMetadata(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("setupCommandK8sMetadata took %s (created %d metadata fields in Command)", time.Since(start), len(commandMetadataMap))
	}

	for i := 0; i < 10; i++ {
		// Now log the time required to check that the metadata is correctly configured
		start := time.Now()
		err = signer.setupCommandK8sMetadata(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("setupCommandK8sMetadata took %s (verified %d metadata fields in Command)", time.Since(start), len(commandMetadataMap))
	}
}

func deleteCommandK8sMetadataItems(t *testing.T, client *keyfactor.APIClient) error {
	metadataFields, _, err := client.MetadataFieldApi.MetadataFieldGetAllMetadataFields(context.Background()).Execute()
	if err != nil {
		return err
	}

	existingMetaMap := make(map[string]int32)
	for _, field := range metadataFields {
		existingMetaMap[*field.Name] = *field.Id
	}

	for metaName, description := range commandMetadataMap {
		if id, ok := existingMetaMap[metaName]; ok {
			t.Logf("Deleting metadata field %s \"%s\" (%d)", metaName, description, id)
			_, err = client.MetadataFieldApi.MetadataFieldDeleteMetadataField(context.Background(), id).Execute()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func getTestSignerConfigItems(t *testing.T) (context.Context, *commandissuer.IssuerSpec, map[string][]byte) {
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

	return context.Background(), &spec, secretData
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
