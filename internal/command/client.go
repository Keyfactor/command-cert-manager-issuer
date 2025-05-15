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
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	commandsdk "github.com/Keyfactor/keyfactor-go-client/v3/api"
	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var (
	tokenCredentialSource TokenCredentialSource
)

func getAmbientTokenCredentialSource() TokenCredentialSource {
	return tokenCredentialSource
}

func setAmbientTokenCredentialSource(source TokenCredentialSource) {
	tokenCredentialSource = source
}

type Client interface {
	EnrollCSR(ea *commandsdk.EnrollCSRFctArgs) (*commandsdk.EnrollResponse, error)
	GetAllMetadataFields() ([]commandsdk.MetadataField, error)
	TestConnection() error
}

var (
	_ Client = &clientAdapter{}
)

type clientAdapter struct {
	enrollCSR            func(ea *commandsdk.EnrollCSRFctArgs) (*commandsdk.EnrollResponse, error)
	getAllMetadataFields func() ([]commandsdk.MetadataField, error)
	testConnection       func() error
}

// EnrollCSR implements CertificateClient.
func (c *clientAdapter) EnrollCSR(ea *commandsdk.EnrollCSRFctArgs) (*commandsdk.EnrollResponse, error) {
	return c.enrollCSR(ea)
}

// GetAllMetadataFields implements Client.
func (c *clientAdapter) GetAllMetadataFields() ([]commandsdk.MetadataField, error) {
	return c.getAllMetadataFields()
}

// TestConnection implements CertificateClient.
func (c *clientAdapter) TestConnection() error {
	return c.testConnection()
}

type TokenCredentialSource interface {
	GetAccessToken(context.Context) (string, error)
}

var (
	_ TokenCredentialSource = &azure{}
)

func getValueOrDefault(configValue string, defaultValue string) string {
	if configValue != "" {
		return configValue
	}
	return defaultValue
}

type azure struct {
	cred   azcore.TokenCredential
	scopes []string
}

// GetAccessToken implements TokenCredential.
func (a *azure) GetAccessToken(ctx context.Context) (string, error) {
	log := log.FromContext(ctx)

	// To prevent clogging logs every time JWT is generated
	initializing := a.cred == nil

	// Lazily create the credential if needed
	if a.cred == nil {
		c, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return "", fmt.Errorf("%w: failed to set up Azure Default Credential: %w", errTokenFetchFailure, err)
		}
		a.cred = c
	}

	log.Info(fmt.Sprintf("generating Default Azure Credentials with scopes %s", strings.Join(a.scopes, " ")))

	// Request a token with the provided scopes
	token, err := a.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: a.scopes,
	})
	if err != nil {
		return "", fmt.Errorf("%w: failed to fetch token: %w", errTokenFetchFailure, err)
	}

	tokenString := token.Token

	if initializing {
		// Only want to output this once, don't want to output this every time the JWT is generated

		log.Info("==== BEGIN DEBUG: DefaultAzureCredential JWT ======")

		printClaims(log, tokenString, []string{"aud", "azp", "iss", "sub", "oid"})

		log.Info("==== END DEBUG: DefaultAzureCredential JWT ======")
	}

	log.Info("fetched token using Azure DefaultAzureCredential")
	return tokenString, nil
}

func newAzureDefaultCredentialSource(ctx context.Context, scopes []string) (*azure, error) {
	source := &azure{
		scopes: scopes,
	}
	_, err := source.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}

	tokenCredentialSource = source

	return source, nil
}

var (
	_ TokenCredentialSource = &gcp{}
)

type gcp struct {
	tokenSource oauth2.TokenSource
	audience    string
	scopes      []string
}

// GetAccessToken implements TokenCredential.
func (g *gcp) GetAccessToken(ctx context.Context) (string, error) {
	log := log.FromContext(ctx)

	// To prevent clogging logs every time JWT is generated
	initializing := g.tokenSource == nil

	// Lazily create the TokenSource if it's nil.
	if g.tokenSource == nil {
		log.Info(fmt.Sprintf("generating default Google credentials with scopes: %s", strings.Join(g.scopes, " ")))

		credentials, err := google.FindDefaultCredentials(ctx, g.scopes...)
		if err != nil {
			return "", fmt.Errorf("%w: failed to find GCP ADC: %w", errTokenFetchFailure, err)
		}
		log.Info(fmt.Sprintf("generating a Google OIDC ID token..."))

		// Default audience to "command" if not provided
		aud := getValueOrDefault(g.audience, "command")

		log.Info(fmt.Sprintf("generating Google id token with audience %s", aud))

		// Use credentials to generate a JWT (requires a service account)
		tokenSource, err := idtoken.NewTokenSource(ctx, aud, idtoken.WithCredentialsJSON(credentials.JSON))
		if err != nil {
			return "", fmt.Errorf("%w: failed to get GCP ID Token Source: %w", errTokenFetchFailure, err)
		}

		_, err = tokenSource.Token()
		if err != nil {
			return "", fmt.Errorf("%w: failed to generate GCP JWT Token from token source: %w", errTokenFetchFailure, err)
		}

		g.tokenSource = tokenSource
	}

	// Retrieve the token from the token source.
	token, err := g.tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("%w: failed to fetch token from GCP ADC token source: %w", errTokenFetchFailure, err)
	}

	if initializing {
		// Only want to output this once, don't want to output this every time the JWT is generated

		log.Info("==== BEGIN DEBUG: Default Google ID Token JWT ======")
		printClaims(log, token.AccessToken, []string{"aud", "iss", "sub", "email"})
		log.Info("==== END DEBUG:  Default Google ID Token JWT ======")
	}

	log.Info("fetched token using GCP ApplicationDefaultCredential")

	return token.AccessToken, nil
}

func newGCPDefaultCredentialSource(ctx context.Context, audience string, scopes []string) (*gcp, error) {
	source := &gcp{
		scopes:   scopes,
		audience: audience,
	}
	_, err := source.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	tokenCredentialSource = source
	return source, nil
}

func printClaims(log logr.Logger, token string, claimsToPrint []string) error {
	tokenRaw, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		log.Error(err, "failed to parse JWT")
		return fmt.Errorf("failed to parse JWT: %w", err)
	}

	claims, _ := tokenRaw.Claims.(jwt.MapClaims)

	for _, key := range claimsToPrint {
		if value, ok := claims[key]; ok {
			log.Info(fmt.Sprintf("	%s:	%s", key, value))
		}
	}

	return nil
}
