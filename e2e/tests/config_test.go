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

// Package tests is the e2e test suite. It assumes the infrastructure already
// exists (see ../cmd/setup) and only exercises it: it never installs
// cert-manager or deploys the issuer.
package tests

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/Keyfactor/command-cert-manager-issuer/e2e/internal/e2econfig"
	"github.com/Keyfactor/command-cert-manager-issuer/e2e/internal/envfile"
)

// Environment variables read only by the test suite. They describe the Command
// instance the Issuer under test talks to; the credentials for it live in the
// auth Secret created by setup, which the tests never read.
const (
	envKubeContext       = "E2E_KUBE_CONTEXT"
	envEnvFile           = "E2E_ENV_FILE"
	envKeepResources     = "E2E_KEEP_RESOURCES"
	envCommandHostname   = "E2E_COMMAND_HOSTNAME"
	envCommandAPIPath    = "E2E_COMMAND_API_PATH"
	envCertTemplate      = "E2E_CERTIFICATE_TEMPLATE"
	envCALogicalName     = "E2E_CERTIFICATE_AUTHORITY_LOGICAL_NAME"
	envCAHostname        = "E2E_CERTIFICATE_AUTHORITY_HOSTNAME"
	envEnrollmentPattern = "E2E_ENROLLMENT_PATTERN_NAME"
	envOwnerRole         = "E2E_OWNER_ROLE_NAME"
	envCommonName        = "E2E_CERTIFICATE_COMMON_NAME"
)

type config struct {
	kubeContext   string
	keepResources bool

	// Where setup put things. Shared with the setup tool through e2econfig.
	namespace      string
	releaseName    string
	authSecretName string
	caSecretName   string

	// Issuer spec.
	hostname              string
	apiPath               string
	certificateTemplate   string
	caLogicalName         string
	caHostname            string
	enrollmentPatternName string
	ownerRoleName         string

	commonName string
}

// Reads the environment, first loading the env file shared with the
// setup tool if there is one.
func loadConfig() (config, error) {
	path := os.Getenv(envEnvFile)
	if path == "" {
		// go test runs in the package directory, which is e2e/tests.
		if _, err := os.Stat("../" + e2econfig.DefaultEnvFile); err == nil {
			path = "../" + e2econfig.DefaultEnvFile
		}
	}
	if path != "" {
		if err := envfile.Load(path); err != nil {
			return config{}, err
		}
		fmt.Println("Loaded environment from", path)
	}

	c := config{
		kubeContext:   os.Getenv(envKubeContext),
		keepResources: strings.EqualFold(os.Getenv(envKeepResources), "true"),

		namespace:      e2econfig.Namespace(),
		releaseName:    e2econfig.ReleaseName(),
		authSecretName: e2econfig.AuthSecretName(),
		caSecretName:   e2econfig.CASecretName(),

		hostname:              os.Getenv(envCommandHostname),
		apiPath:               e2econfig.EnvOr(envCommandAPIPath, "KeyfactorAPI"),
		certificateTemplate:   os.Getenv(envCertTemplate),
		caLogicalName:         os.Getenv(envCALogicalName),
		caHostname:            os.Getenv(envCAHostname),
		enrollmentPatternName: os.Getenv(envEnrollmentPattern),
		ownerRoleName:         os.Getenv(envOwnerRole),

		commonName: e2econfig.EnvOr(envCommonName, "example.com"),
	}

	var missing []string
	for name, v := range map[string]string{
		envCommandHostname: c.hostname,
		envCertTemplate:    c.certificateTemplate,
		envCALogicalName:   c.caLogicalName,
	} {
		if v == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return c, errors.New("required environment variables are not set: " + strings.Join(missing, ", "))
	}
	return c, nil
}
