//go:build e2e

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

package tests

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"
	"time"

	cmapiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commandissuer "github.com/Keyfactor/command-cert-manager-issuer/api/v1alpha1"
)

const (
	issuerReadyTimeout    = 60 * time.Second
	requestCreatedTimeout = 30 * time.Second
	issuedTimeout         = 2 * time.Minute
	certReadyTimeout      = 60 * time.Second
)

// TestCertificateRequestIsIssued checks the core flow: a Certificate makes
// cert-manager create a CertificateRequest, and once that request is approved
// the issuer has Command sign it and the resulting certificate lands in the
// Certificate's Secret.
func TestCertificateRequestIsIssued(t *testing.T) {
	ns := createTestNamespace(t)

	issuer := createIssuer(t, ns)
	waitForIssuerReady(t, issuer)

	cert := createCertificate(t, ns, issuer)

	cr := waitForCertificateRequest(t, cert)
	approveCertificateRequest(t, cr)

	waitForCertificateRequestIssued(t, cr)
	waitForCertificateReady(t, cert)

	verifyCertificateSecret(t, cert)
}

// Creates a new Issuer resource in the specified namespace and returns it.
func createIssuer(t *testing.T, ns string) *commandissuer.Issuer {
	t.Helper()
	cfg := suite.cfg

	issuer := &commandissuer.Issuer{
		ObjectMeta: metav1.ObjectMeta{Name: "issuer", Namespace: ns},
		Spec: commandissuer.IssuerSpec{
			Hostname:                        cfg.hostname,
			APIPath:                         cfg.apiPath,
			SecretName:                      cfg.authSecretName,
			CertificateTemplate:             cfg.certificateTemplate,
			CertificateAuthorityLogicalName: cfg.caLogicalName,
			CertificateAuthorityHostname:    cfg.caHostname,
			EnrollmentPatternName:           cfg.enrollmentPatternName,
			OwnerRoleName:                   cfg.ownerRoleName,
		},
	}
	if suite.caSecretPresent {
		issuer.Spec.CaSecretName = cfg.caSecretName
	}

	if err := suite.client.Create(context.Background(), issuer); err != nil {
		t.Fatalf("creating Issuer: %v", err)
	}
	return issuer
}

// Waits for the Issuer to reach the Ready condition.
func waitForIssuerReady(t *testing.T, issuer *commandissuer.Issuer) {
	t.Helper()

	waitFor(t, fmt.Sprintf("Issuer %s/%s to be Ready", issuer.Namespace, issuer.Name), issuerReadyTimeout,
		func(ctx context.Context) (bool, string, error) {
			if err := suite.client.Get(ctx, client.ObjectKeyFromObject(issuer), issuer); err != nil {
				return false, "", err
			}
			if issuer.Status.HasCondition(commandissuer.IssuerConditionReady, commandissuer.ConditionTrue) {
				return true, "", nil
			}
			return false, fmt.Sprintf("conditions: %+v", issuer.Status.Conditions), nil
		})
}

// Creates a Certificate resource in the given namespace using the specified Issuer.
// cert-manager will take care of generating the corresponding CertificateRequest and managing the certificate lifecycle.
func createCertificate(t *testing.T, ns string, issuer *commandissuer.Issuer) *cmapi.Certificate {
	t.Helper()

	cert := &cmapi.Certificate{
		ObjectMeta: metav1.ObjectMeta{Name: "e2e-cert", Namespace: ns},
		Spec: cmapi.CertificateSpec{
			SecretName: "e2e-cert-tls",
			CommonName: suite.cfg.commonName,
			Usages:     []cmapi.KeyUsage{cmapi.UsageSigning, cmapi.UsageDigitalSignature, cmapi.UsageServerAuth},
			Duration:   &metav1.Duration{Duration: 90 * 24 * time.Hour},
			PrivateKey: &cmapi.CertificatePrivateKey{Algorithm: cmapi.RSAKeyAlgorithm, Size: 2048},
			IssuerRef: cmmeta.ObjectReference{
				Name:  issuer.Name,
				Kind:  "Issuer",
				Group: commandissuer.GroupVersion.Group,
			},
		},
	}
	if err := suite.client.Create(context.Background(), cert); err != nil {
		t.Fatalf("creating Certificate: %v", err)
	}
	return cert
}

// Waits for cert-manager to create the CertificateRequest for cert, and returns it.
func waitForCertificateRequest(t *testing.T, cert *cmapi.Certificate) *cmapi.CertificateRequest {
	t.Helper()

	var found *cmapi.CertificateRequest
	waitFor(t, fmt.Sprintf("cert-manager to create a CertificateRequest for Certificate %s/%s", cert.Namespace, cert.Name), requestCreatedTimeout,
		func(ctx context.Context) (bool, string, error) {
			var list cmapi.CertificateRequestList
			if err := suite.client.List(ctx, &list, client.InNamespace(cert.Namespace)); err != nil {
				return false, "", err
			}
			for i := range list.Items {
				if metav1.IsControlledBy(&list.Items[i], cert) {
					found = &list.Items[i]
					return true, "", nil
				}
			}
			return false, fmt.Sprintf("%d CertificateRequests in namespace, none owned by the Certificate", len(list.Items)), nil
		})

	t.Logf("cert-manager created CertificateRequest %s", found.Name)
	return found
}

// Approves the certificate request the way `cmctl approve` does. cert-manager
// only auto-approves requests for its own issuer types, so requests for this
// issuer wait for an approver. This needs permission to approve for the
// issuer's signer name.
func approveCertificateRequest(t *testing.T, cr *cmapi.CertificateRequest) {
	t.Helper()

	err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		ctx := context.Background()
		if err := suite.client.Get(ctx, client.ObjectKeyFromObject(cr), cr); err != nil {
			return err
		}
		cmapiutil.SetCertificateRequestCondition(cr, cmapi.CertificateRequestConditionApproved,
			cmmeta.ConditionTrue, "e2e.command-issuer.keyfactor.com", "Approved by the e2e test suite")
		return suite.client.Status().Update(ctx, cr)
	})
	if err != nil {
		t.Fatalf("approving CertificateRequest %s (does your kubeconfig user have permission to approve requests for issuers.command-issuer.keyfactor.com?): %v", cr.Name, err)
	}
}

// Waits for the issuer / cluster issuer to sign the CertificateRequest. A request
// that was denied or failed will never recover, so those fail immediately.
func waitForCertificateRequestIssued(t *testing.T, cr *cmapi.CertificateRequest) {
	t.Helper()

	waitFor(t, fmt.Sprintf("CertificateRequest %s to be issued", cr.Name), issuedTimeout,
		func(ctx context.Context) (bool, string, error) {
			if err := suite.client.Get(ctx, client.ObjectKeyFromObject(cr), cr); err != nil {
				return false, "", err
			}

			for _, c := range cr.Status.Conditions {
				if c.Type == cmapi.CertificateRequestConditionReady && c.Status == cmmeta.ConditionTrue {
					return true, "", nil
				}
				if c.Type == cmapi.CertificateRequestConditionReady && c.Reason == cmapi.CertificateRequestReasonFailed {
					t.Fatalf("CertificateRequest %s failed: %s", cr.Name, c.Message)
				}
				if c.Type == cmapi.CertificateRequestConditionDenied && c.Status == cmmeta.ConditionTrue {
					t.Fatalf("CertificateRequest %s was denied: %s", cr.Name, c.Message)
				}
			}
			return false, fmt.Sprintf("conditions: %+v", cr.Status.Conditions), nil
		})
}

// Waits for the Certificate resource to reach the Ready condition.
func waitForCertificateReady(t *testing.T, cert *cmapi.Certificate) {
	t.Helper()

	waitFor(t, fmt.Sprintf("Certificate %s/%s to be Ready", cert.Namespace, cert.Name), certReadyTimeout,
		func(ctx context.Context) (bool, string, error) {
			if err := suite.client.Get(ctx, client.ObjectKeyFromObject(cert), cert); err != nil {
				return false, "", err
			}
			for _, c := range cert.Status.Conditions {
				if c.Type == cmapi.CertificateConditionReady && c.Status == cmmeta.ConditionTrue {
					return true, "", nil
				}
			}
			return false, fmt.Sprintf("conditions: %+v", cert.Status.Conditions), nil
		})
}

// Checks that the generated Certificate Secret holds a usable key pair for
// the requested identity, not merely that it exists.
func verifyCertificateSecret(t *testing.T, cert *cmapi.Certificate) {
	t.Helper()

	var secret corev1.Secret
	key := types.NamespacedName{Namespace: cert.Namespace, Name: cert.Spec.SecretName}
	if err := suite.client.Get(context.Background(), key, &secret); err != nil {
		t.Fatalf("getting certificate Secret %s: %v", key, err)
	}

	crt, privKey := secret.Data[corev1.TLSCertKey], secret.Data[corev1.TLSPrivateKeyKey]
	if len(crt) == 0 || len(privKey) == 0 {
		t.Fatalf("Secret %s is missing %s or %s", key, corev1.TLSCertKey, corev1.TLSPrivateKeyKey)
	}

	// Fails if the certificate is not valid PEM or does not match the private key.
	if _, err := tls.X509KeyPair(crt, privKey); err != nil {
		t.Fatalf("Secret %s does not hold a matching certificate and key: %v", key, err)
	}

	block, _ := pem.Decode(bytes.TrimSpace(crt))
	if block == nil {
		t.Fatalf("Secret %s: %s contains no PEM block", key, corev1.TLSCertKey)
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("Secret %s: parsing leaf certificate: %v", key, err)
	}

	if leaf.Subject.CommonName != cert.Spec.CommonName {
		t.Errorf("issued certificate has CN %q, want %q", leaf.Subject.CommonName, cert.Spec.CommonName)
	}
	if now := time.Now(); now.Before(leaf.NotBefore.Add(-5*time.Minute)) || now.After(leaf.NotAfter) {
		t.Errorf("issued certificate is not currently valid (valid %s to %s)", leaf.NotBefore, leaf.NotAfter)
	}
	t.Logf("issued certificate: CN=%s, issuer=%s, serial=%s, expires %s",
		leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.SerialNumber, leaf.NotAfter.Format(time.RFC3339))
}
