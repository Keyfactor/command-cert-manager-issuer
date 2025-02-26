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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	commandsdk "github.com/Keyfactor/keyfactor-go-client/v3/api"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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

type azure struct {
	cred   azcore.TokenCredential
	scopes []string
}

// GetAccessToken implements TokenCredential.
func (a *azure) GetAccessToken(ctx context.Context) (string, error) {
	// Lazily create the credential if needed
	if a.cred == nil {
		c, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			return "", fmt.Errorf("%w: failed to set up Azure Default Credential: %w", errTokenFetchFailure, err)
		}
		a.cred = c
	}

	// Request a token with the provided scopes
	token, err := a.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: a.scopes,
	})
	if err != nil {
		return "", fmt.Errorf("%w: failed to fetch token: %w", errTokenFetchFailure, err)
	}

	log.FromContext(ctx).Info("fetched token using Azure DefaultAzureCredential")
	return token.Token, nil
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
	scopes      []string
}

// GetAccessToken implements TokenCredential.
func (g *gcp) GetAccessToken(ctx context.Context) (string, error) {
	// Lazily create the TokenSource if it's nil.
	if g.tokenSource == nil {
		credentials, err := google.FindDefaultCredentials(ctx, g.scopes...)
		if err != nil {
			return "", fmt.Errorf("%w: failed to find GCP ADC: %w", errTokenFetchFailure, err)
		}

		// Use credentials to generate a JWT (requires a service account)
		jwtSource, err := google.JWTAccessTokenSourceWithScope(credentials.JSON, g.scopes...)
		if err != nil {
			return "", fmt.Errorf("%w: failed to generate GCP JWT Access Token Source: %w", errTokenFetchFailure, err)
		}

		g.tokenSource = jwtSource
	}

	// Retrieve the token from the token source.
	token, err := g.tokenSource.Token()
	if err != nil {
		return "", fmt.Errorf("%w: failed to fetch token from GCP ADC token source: %w", errTokenFetchFailure, err)
	}

	log.FromContext(ctx).Info("fetched token using GCP ApplicationDefaultCredential")
	return token.AccessToken, nil
}

func newGCPDefaultCredentialSource(ctx context.Context, scopes []string) (*gcp, error) {
	source := &gcp{
		scopes: scopes,
	}
	_, err := source.GetAccessToken(ctx)
	if err != nil {
		return nil, err
	}
	tokenCredentialSource = source
	return source, nil
}
