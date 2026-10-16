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
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/controller-runtime/pkg/client"

	commandissuer "github.com/Keyfactor/command-cert-manager-issuer/api/v1alpha1"
)

// suite is the state shared by all tests, built once in TestMain.
var suite struct {
	cfg    config
	client client.Client

	// caSecretPresent is true if setup created the CA trust Secret, in which case Issuers reference it.
	caSecretPresent bool
}

func TestMain(m *testing.M) {
	os.Exit(run(m))
}

func run(m *testing.M) int {
	cfg, err := loadConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: configuration error:", err)
		fmt.Fprintln(os.Stderr, "See e2e/README.md for the variables the tests need.")
		return 1
	}
	suite.cfg = cfg

	scheme := runtime.NewScheme()
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(cmapi.AddToScheme(scheme))
	utilruntime.Must(commandissuer.AddToScheme(scheme))

	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		clientcmd.NewDefaultClientConfigLoadingRules(),
		&clientcmd.ConfigOverrides{CurrentContext: cfg.kubeContext},
	)
	restCfg, err := cc.ClientConfig()
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: cannot load kubeconfig:", err)
		return 1
	}
	suite.client, err = client.New(restCfg, client.Options{Scheme: scheme})
	if err != nil {
		fmt.Fprintln(os.Stderr, "e2e: cannot create Kubernetes client:", err)
		return 1
	}

	kubeContext := cfg.kubeContext
	if raw, err := cc.RawConfig(); err == nil && kubeContext == "" {
		kubeContext = raw.CurrentContext
	}
	fmt.Printf("e2e: running against context %q (%s)\n", kubeContext, restCfg.Host)
	fmt.Println("e2e: tests create and delete their own e2e-* namespaces in this cluster.")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if problems := preflight(ctx); len(problems) > 0 {
		fmt.Fprintln(os.Stderr, "\ne2e: the target cluster is not ready for the tests:")
		for _, p := range problems {
			fmt.Fprintln(os.Stderr, "  -", p)
		}
		fmt.Fprintln(os.Stderr, "\nRun `make e2e-setup` to prepare the cluster, then try again.")
		return 1
	}

	return m.Run()
}

// Verifies that setup has been run against the cluster. It reports
// every problem it finds rather than stopping at the first.
func preflight(ctx context.Context) []string {
	var problems []string
	c := suite.client
	cfg := suite.cfg

	if err := c.List(ctx, &cmapi.CertificateList{}, client.Limit(1)); err != nil {
		problems = append(problems, fmt.Sprintf("cert-manager is not installed or not reachable (listing Certificates failed: %v)", err))
	}
	if err := c.List(ctx, &commandissuer.IssuerList{}, client.Limit(1)); err != nil {
		problems = append(problems, fmt.Sprintf("the Issuer CRDs are not installed (listing Issuers failed: %v)", err))
	}

	var dep appsv1.Deployment
	switch err := c.Get(ctx, types.NamespacedName{Namespace: cfg.namespace, Name: cfg.releaseName}, &dep); {
	case apierrors.IsNotFound(err):
		problems = append(problems, fmt.Sprintf("issuer Deployment %s/%s not found", cfg.namespace, cfg.releaseName))
	case err != nil:
		problems = append(problems, fmt.Sprintf("cannot read issuer Deployment %s/%s: %v", cfg.namespace, cfg.releaseName, err))
	case dep.Status.AvailableReplicas < 1:
		problems = append(problems, fmt.Sprintf("issuer Deployment %s/%s has no available replicas", cfg.namespace, cfg.releaseName))
	}

	// Only existence is checked; the tests never read the credentials.
	var secret corev1.Secret
	switch err := c.Get(ctx, types.NamespacedName{Namespace: cfg.namespace, Name: cfg.authSecretName}, &secret); {
	case apierrors.IsNotFound(err):
		problems = append(problems, fmt.Sprintf("auth Secret %s/%s not found", cfg.namespace, cfg.authSecretName))
	case err != nil:
		problems = append(problems, fmt.Sprintf("cannot read auth Secret %s/%s: %v", cfg.namespace, cfg.authSecretName, err))
	}

	// The CA trust Secret is optional.
	err := c.Get(ctx, types.NamespacedName{Namespace: cfg.namespace, Name: cfg.caSecretName}, &corev1.Secret{})
	suite.caSecretPresent = err == nil

	return problems
}
