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

// Command setup prepares a Kubernetes cluster for the e2e test suite: it makes
// sure cert-manager is installed, deploys command-cert-manager-issuer, and
// creates the Secrets the issuer needs to talk to Keyfactor Command.
//
// It deliberately does not create Issuer resources; the test suite owns those.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/Keyfactor/command-cert-manager-issuer/e2e/internal/e2econfig"
	"github.com/Keyfactor/command-cert-manager-issuer/e2e/internal/envfile"
)

const usage = `Usage: go run ./cmd/setup [setup|teardown] [flags]

Commands:
  setup      Install cert-manager (if missing), deploy command-cert-manager-issuer,
             and create the auth (and optional CA trust) Secrets. This is the default.
  teardown   Uninstall command-cert-manager-issuer and delete the Secrets created by setup.
             cert-manager and the namespace are left in place.

Run 'go run ./cmd/setup <command> -h' for the flags of a command.
`

// Environment variables holding the Command OAuth credentials. These are only
// read from the environment (or --env-file), never from flags, so they cannot
// leak into shell history or process listings.
const (
	envTokenURL     = "E2E_OAUTH_TOKEN_URL"
	envClientID     = "E2E_OAUTH_CLIENT_ID"
	envClientSecret = "E2E_OAUTH_CLIENT_SECRET"
	envAudience     = "E2E_OAUTH_AUDIENCE"
	envScopes       = "E2E_OAUTH_SCOPES"
)

const (
	localTag           = "local"
	defaultImageRepo   = "keyfactor/command-cert-manager-issuer"
	chartRepoURL       = "https://keyfactor.github.io/command-cert-manager-issuer"
	chartName          = "command-cert-manager-issuer"
	localChartRelPath  = "deploy/charts/command-cert-manager-issuer"
	certManagerRepoURL = "https://charts.jetstack.io"
	certManagerCRD     = "certificates.cert-manager.io"
)

type options struct {
	envFile     string
	kubeContext string
	yes         bool

	namespace      string
	releaseName    string
	authSecretName string
	caSecretName   string

	chartVersion    string
	imageTag        string
	imageRepository string
	push            bool

	certManagerVersion string
	caCertsDir         string
	repoRoot           string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := run(ctx, os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string) error {
	cmd := "setup"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}

	switch cmd {
	case "setup":
		return runSetup(ctx, args)
	case "teardown":
		return runTeardown(ctx, args)
	case "help":
		fmt.Print(usage)
		return nil
	default:
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

// registerCommonFlags adds the flags shared by setup and teardown. Flags that
// have an environment variable fallback default to "" here and are resolved
// after the env file is loaded.
func registerCommonFlags(fs *flag.FlagSet, o *options) {
	fs.StringVar(&o.envFile, "env-file", "", "File of KEY=VALUE lines to load into the environment (default: "+e2econfig.DefaultEnvFile+" if it exists). Variables already set are not overridden.")
	fs.StringVar(&o.kubeContext, "context", "", "kubeconfig context to deploy to (default: the current context). You are asked to confirm it.")
	fs.BoolVar(&o.yes, "yes", false, "Skip the interactive confirmation. Required when stdin is not a terminal.")
	fs.StringVar(&o.namespace, "namespace", "", "Namespace for the issuer and its Secrets (env "+e2econfig.EnvNamespace+", default "+e2econfig.DefaultNamespace+")")
	fs.StringVar(&o.releaseName, "release-name", "", "Helm release name, also used as the Deployment name (env "+e2econfig.EnvReleaseName+", default "+e2econfig.DefaultReleaseName+")")
	fs.StringVar(&o.authSecretName, "auth-secret-name", "", "Name of the Command credentials Secret (env "+e2econfig.EnvAuthSecretName+", default "+e2econfig.DefaultAuthSecretName+")")
	fs.StringVar(&o.caSecretName, "ca-secret-name", "", "Name of the CA trust Secret (env "+e2econfig.EnvCASecretName+", default "+e2econfig.DefaultCASecretName+")")
	fs.StringVar(&o.repoRoot, "repo-root", "", "Repository root (default: found by walking up from the working directory)")
}

// resolveCommon loads the env file and fills in anything still unset from the
// environment and defaults.
func resolveCommon(o *options) error {
	if o.envFile == "" {
		if _, err := os.Stat(e2econfig.DefaultEnvFile); err == nil {
			o.envFile = e2econfig.DefaultEnvFile
		}
	}
	if o.envFile != "" {
		if err := envfile.Load(o.envFile); err != nil {
			return err
		}
		fmt.Println("Loaded environment from", o.envFile)
	}
	if o.namespace == "" {
		o.namespace = e2econfig.Namespace()
	}
	if o.releaseName == "" {
		o.releaseName = e2econfig.ReleaseName()
	}
	if o.authSecretName == "" {
		o.authSecretName = e2econfig.AuthSecretName()
	}
	if o.caSecretName == "" {
		o.caSecretName = e2econfig.CASecretName()
	}
	if o.repoRoot == "" {
		if wd, err := os.Getwd(); err == nil {
			o.repoRoot = findRepoRoot(wd)
		}
	}
	return nil
}

// findRepoRoot walks up from dir looking for the issuer's Helm chart. It
// returns "" if the chart is not found.
func findRepoRoot(dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, localChartRelPath, "Chart.yaml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// resolveContext returns the kubeconfig context to use and its API server URL.
func resolveContext(ctx context.Context, requested string) (name, server string, err error) {
	name = requested
	if name == "" {
		name, err = execCmd(ctx, execOpts{quiet: true}, "kubectl", "config", "current-context")
		if err != nil {
			return "", "", fmt.Errorf("no --context given and no current context is set: %w", err)
		}
	}

	server, err = execCmd(ctx, execOpts{quiet: true}, "kubectl", "config", "view", "--minify", "--context", name,
		"-o", "jsonpath={.clusters[0].cluster.server}")
	if err != nil {
		return "", "", fmt.Errorf("context %q not found in kubeconfig: %w", name, err)
	}
	return name, server, nil
}

func step(format string, a ...any) {
	fmt.Printf("\n==> "+format+"\n", a...)
}
