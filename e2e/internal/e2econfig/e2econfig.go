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

// Package e2econfig defines the contract between the e2e setup tool, which
// provisions the infrastructure, and the e2e test suite, which assumes that
// infrastructure already exists. Both read the same environment variables and
// fall back to the same defaults, so they agree on where things live.
package e2econfig

import "os"

// Environment variables shared by the setup tool and the test suite.
const (
	EnvNamespace      = "E2E_NAMESPACE"
	EnvReleaseName    = "E2E_RELEASE_NAME"
	EnvAuthSecretName = "E2E_AUTH_SECRET_NAME"
	EnvCASecretName   = "E2E_CA_SECRET_NAME"
)

// Defaults used when the corresponding environment variable is unset.
const (
	DefaultNamespace      = "command-issuer-system"
	DefaultReleaseName    = "command-cert-manager-issuer"
	DefaultAuthSecretName = "auth-secret"
	DefaultCASecretName   = "ca-trust-secret"

	// DefaultEnvFile is the optional file, relative to the e2e directory, that both the
	// setup tool and the test suite load their environment from.
	DefaultEnvFile = "e2e.env"

	// CertManagerNamespace is where cert-manager is installed by the setup tool.
	CertManagerNamespace = "cert-manager"
)

// Namespace is the namespace the issuer is deployed to. With the chart's
// default settings, the auth and CA secrets must live in this namespace.
func Namespace() string { return EnvOr(EnvNamespace, DefaultNamespace) }

// ReleaseName is the Helm release name of the issuer. The chart derives the
// Deployment name from it.
func ReleaseName() string { return EnvOr(EnvReleaseName, DefaultReleaseName) }

// AuthSecretName is the name of the Secret holding the Command OAuth credentials.
func AuthSecretName() string { return EnvOr(EnvAuthSecretName, DefaultAuthSecretName) }

// CASecretName is the name of the Secret holding CA certificates to trust when
// connecting to Command.
func CASecretName() string { return EnvOr(EnvCASecretName, DefaultCASecretName) }

// EnvOr returns the value of the environment variable key, or def if it is unset or empty.
func EnvOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
