/*
Copyright © 2025 Keyfactor

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
	"io"
	"net/http"
	"sync"
	"time"

	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/go-logr/logr"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/idtoken"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Client interface {
	EnrollCSR(v1.ApiCreateEnrollmentCSRRequest) (*v1.CSSCMSDataModelModelsEnrollmentCSREnrollmentResponse, *http.Response, error)
	GetAllMetadataFields(v1.ApiGetMetadataFieldsRequest) ([]v1.CSSCMSDataModelModelsMetadataType, error)
	GetEnrollmentPatterns(v1.ApiGetEnrollmentPatternsRequest) ([]v1.EnrollmentPatternsEnrollmentPatternResponse, *http.Response, error)
	TestConnection() error
}

var (
	_ Client = &clientAdapter{}
)

type clientAdapter struct {
	enrollCSR             func(r v1.ApiCreateEnrollmentCSRRequest) (*v1.CSSCMSDataModelModelsEnrollmentCSREnrollmentResponse, *http.Response, error)
	getAllMetadataFields  func(r v1.ApiGetMetadataFieldsRequest) ([]v1.CSSCMSDataModelModelsMetadataType, *http.Response, error)
	getEnrollmentPatterns func(r v1.ApiGetEnrollmentPatternsRequest) ([]v1.EnrollmentPatternsEnrollmentPatternResponse, *http.Response, error)
	testConnection        func() error
}

// GetAllMetadataFields implements Client. Closes the response body internally so callers don't need to.
func (c *clientAdapter) GetAllMetadataFields(r v1.ApiGetMetadataFieldsRequest) ([]v1.CSSCMSDataModelModelsMetadataType, error) {
	fields, resp, err := c.getAllMetadataFields(r)
	if resp != nil && resp.Body != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return fields, err
}

// EnrollCSR implements CertificateClient.
func (c *clientAdapter) EnrollCSR(r v1.ApiCreateEnrollmentCSRRequest) (*v1.CSSCMSDataModelModelsEnrollmentCSREnrollmentResponse, *http.Response, error) {
	return c.enrollCSR(r)
}

func (c *clientAdapter) GetEnrollmentPatterns(r v1.ApiGetEnrollmentPatternsRequest) ([]v1.EnrollmentPatternsEnrollmentPatternResponse, *http.Response, error) {
	return c.getEnrollmentPatterns(r)
}

// TestConnection implements CertificateClient.
func (c *clientAdapter) TestConnection() error {
	return c.testConnection()
}

func getValueOrDefault(configValue string, defaultValue string) string {
	if configValue != "" {
		return configValue
	}
	return defaultValue
}

type azureTokenSource struct {
	ctx    context.Context
	cred   azcore.TokenCredential
	scopes []string

	mu          sync.Mutex
	last        string // last issued token, used to detect rotation
	claimsShown bool   // whether the JWT claims debug block has been printed yet
}

var (
	_ oauth2.TokenSource = &azureTokenSource{}
)

func (a *azureTokenSource) Token() (*oauth2.Token, error) {
	// Try Azure with a short timeout
	timeoutCtx, cancel := context.WithTimeout(a.ctx, 10*time.Second)
	defer cancel()

	tok, err := a.cred.GetToken(timeoutCtx, policy.TokenRequestOptions{
		Scopes: a.scopes,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch token from Azure Default Credential: %w", errTokenFetchFailure, err)
	}

	// Only log when the underlying token has actually rotated - azidentity
	// already caches and renews internally, so most calls return the same
	// token and would otherwise flood the logs since Token() is called on
	// every outbound request.
	a.mu.Lock()
	l := log.FromContext(a.ctx)
	if tok.Token != a.last {
		l.Info(fmt.Sprintf("Access token issued from Azure. Token expires at UTC time %s", tok.ExpiresOn.UTC().Format(time.RFC3339)))
		a.last = tok.Token
	}
	// The claims below (identity, issuer, audience, etc.) are tied to the
	// underlying identity, not the individual token, so they don't change
	// across rotations - only print them once per source instantiation.
	if !a.claimsShown {
		l.Info("==== BEGIN DEBUG: DefaultAzureCredential JWT ======")
		printClaims(l, tok.Token, []string{"aud", "appid", "azp", "iss", "sub", "oid"})
		l.Info("==== END DEBUG: DefaultAzureCredential JWT ======")
		a.claimsShown = true
	}
	a.mu.Unlock()

	return &oauth2.Token{
		AccessToken: tok.Token,
		TokenType:   "Bearer",
		Expiry:      tok.ExpiresOn,
	}, nil
}

func newAzureTokenSource(ctx context.Context, scopes []string) (oauth2.TokenSource, error) {
	log := log.FromContext(ctx)
	log.Info("creating new Azure Default Token Source")

	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to set up Azure Default Credential: %w", errTokenFetchFailure, err)
	}

	// ctx is captured here and reused for every future Token() call for the
	// lifetime of this source, since the resulting client is cached
	// indefinitely by ClientCache.
	ctx = context.WithoutCancel(ctx)

	src := &azureTokenSource{
		ctx:    ctx,
		cred:   cred,
		scopes: scopes,
	}

	// Fail fast if the credentials/scopes are wrong
	if _, err := src.Token(); err != nil {
		return nil, err
	}

	return src, nil
}

type gcpTokenSource struct {
	ctx      context.Context
	mu       sync.Mutex
	inner    oauth2.TokenSource
	last     string // last issued token, used to detect rotation
	audience string
	scopes   []string

	claimsShown bool // whether the JWT claims debug block has been printed yet
}

var (
	_ oauth2.TokenSource = &gcpTokenSource{}
)

func (g *gcpTokenSource) Token() (*oauth2.Token, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	log := log.FromContext(g.ctx)

	if g.inner == nil {
		log.Info("initializing GCP token source")
		// Try GCP with a short timeout
		timeoutCtx, cancel := context.WithTimeout(g.ctx, 10*time.Second)
		defer cancel()
		creds, err := google.FindDefaultCredentials(timeoutCtx, g.scopes...)
		if err != nil {
			return nil, fmt.Errorf("%w: failed to find GCP ADC: %w", errTokenFetchFailure, err)
		}

		aud := getValueOrDefault(g.audience, "command")
		ts, err := idtoken.NewTokenSource(g.ctx, aud, idtoken.WithCredentialsJSON(creds.JSON))
		if err != nil {
			return nil, fmt.Errorf("%w: failed to get GCP ID Token Source: %w", errTokenFetchFailure, err)
		}

		g.inner = ts
	}

	token, err := g.inner.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: failed to fetch token from GCP ADC token source: %w", errTokenFetchFailure, err)
	}

	if token.AccessToken != g.last {
		log.Info(fmt.Sprintf("Access token issued from GCP. Token expires at UTC time %s", token.Expiry.UTC().Format(time.RFC3339)))
		g.last = token.AccessToken
	}

	// The claims below (identity, issuer, audience, etc.) are tied to the
	// underlying identity, not the individual token, so they don't change
	// across rotations - only print them once per source instantiation.
	if !g.claimsShown {
		log.Info("==== BEGIN DEBUG: Default Google ID Token JWT ======")
		printClaims(log, token.AccessToken, []string{"aud", "iss", "sub", "email"})
		log.Info("==== END DEBUG:  Default Google ID Token JWT ======")
		g.claimsShown = true
	}

	return token, nil
}

func newGCPTokenSource(ctx context.Context, audience string, scopes []string) (oauth2.TokenSource, error) {

	// ctx is captured here and reused for every future Token() call for the
	// lifetime of this source, since the resulting client is cached
	// indefinitely by ClientCache.
	ctx = context.WithoutCancel(ctx)

	src := &gcpTokenSource{
		ctx:      ctx,
		audience: audience,
		scopes:   scopes,
	}

	// Fail fast if the credentials/scopes are wrong
	if _, err := src.Token(); err != nil {
		return nil, err
	}

	return src, nil
}

func printClaims(log logr.Logger, token string, claimsToPrint []string) {
	tokenRaw, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err != nil {
		log.Error(err, "failed to parse JWT")
		return
	}

	claims, _ := tokenRaw.Claims.(jwt.MapClaims)

	// To assist with troubleshooting, only print access token claims relevant to Command configuration
	for _, key := range claimsToPrint {
		if value, ok := claims[key]; ok {
			log.Info(fmt.Sprintf("\t%s:	%s", key, value))
		}
	}

	if issuer, err := claims.GetIssuer(); err == nil && issuer != "" {
		log.Info(fmt.Sprintf("\nNOTE: If you are receiving a HTTP 401 on requests to Command, make sure an identity provider in Command is configured with '%s' as the authority.\nThe discovery endpoint for your issuer can be found at %s/.well-known/openid-configuration.", issuer, issuer))
	}
}
