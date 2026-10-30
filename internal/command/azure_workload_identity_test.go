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

package command

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/go-logr/logr"
	"github.com/go-logr/logr/funcr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeTokenRequester struct {
	token string
	err   error
	calls []fakeTokenRequest
}

type fakeTokenRequest struct {
	namespace string
	name      string
	audiences []string
	ttl       time.Duration
}

func (f *fakeTokenRequester) RequestToken(_ context.Context, namespace, name string, audiences []string, ttl time.Duration) (string, error) {
	f.calls = append(f.calls, fakeTokenRequest{namespace, name, audiences, ttl})
	if f.err != nil {
		return "", f.err
	}
	// A distinct token per call lets tests tell fresh requests from reuse.
	return f.token + "-" + string(rune('0'+len(f.calls))), nil
}

type fakeAzureCredential struct {
	token azcore.AccessToken
	err   error
	calls int
	opts  policy.TokenRequestOptions
}

func (f *fakeAzureCredential) GetToken(_ context.Context, opts policy.TokenRequestOptions) (azcore.AccessToken, error) {
	f.calls++
	f.opts = opts
	return f.token, f.err
}

func TestServiceAccountAssertion(t *testing.T) {
	t.Run("requests-a-token-for-the-referenced-serviceaccount-with-the-azure-exchange-audience-only", func(t *testing.T) {
		requester := &fakeTokenRequester{token: "sa-token"}

		assertion, err := serviceAccountAssertion(requester, "tenant-a", "sa")(context.Background())

		require.NoError(t, err)
		assert.Equal(t, "sa-token-1", assertion)
		require.Len(t, requester.calls, 1)
		call := requester.calls[0]
		assert.Equal(t, "tenant-a", call.namespace)
		assert.Equal(t, "sa", call.name)
		assert.Equal(t, []string{"api://AzureADTokenExchange"}, call.audiences,
			"the token must be valid for the Azure exchange only, never for the Kubernetes API")
		assert.Equal(t, 10*time.Minute, call.ttl)
	})

	t.Run("requests-a-new-token-on-every-call", func(t *testing.T) {
		requester := &fakeTokenRequester{token: "sa-token"}
		getAssertion := serviceAccountAssertion(requester, "tenant-a", "sa")

		first, err := getAssertion(context.Background())
		require.NoError(t, err)
		second, err := getAssertion(context.Background())
		require.NoError(t, err)

		assert.NotEqual(t, first, second, "an assertion must never be reused")
		assert.Len(t, requester.calls, 2)
	})

	t.Run("each-source-targets-only-its-own-serviceaccount", func(t *testing.T) {
		requester := &fakeTokenRequester{token: "sa-token"}
		_, err := serviceAccountAssertion(requester, "tenant-a", "sa-a")(context.Background())
		require.NoError(t, err)
		_, err = serviceAccountAssertion(requester, "tenant-b", "sa-b")(context.Background())
		require.NoError(t, err)

		require.Len(t, requester.calls, 2)
		assert.Equal(t, "tenant-a/sa-a", requester.calls[0].namespace+"/"+requester.calls[0].name)
		assert.Equal(t, "tenant-b/sa-b", requester.calls[1].namespace+"/"+requester.calls[1].name)
	})

	t.Run("requester-error-is-wrapped-and-no-assertion-is-returned", func(t *testing.T) {
		forbidden := errors.New("forbidden")
		requester := &fakeTokenRequester{err: forbidden}

		assertion, err := serviceAccountAssertion(requester, "tenant-a", "sa")(context.Background())

		require.Error(t, err)
		assert.ErrorIs(t, err, errTokenFetchFailure)
		assert.ErrorIs(t, err, forbidden)
		assert.Contains(t, err.Error(), "tenant-a/sa")
		assert.Empty(t, assertion)
	})
}

func TestNewAzureWorkloadIdentityTokenSourceRejectsBadInput(t *testing.T) {
	validRef := &ServiceAccountRef{Name: "sa", Namespace: "tenant-a"}
	validIdentity := &AzureIdentity{ClientID: "client", TenantID: "tenant"}

	t.Run("nil-arguments", func(t *testing.T) {
		requester := &fakeTokenRequester{token: "t"}
		for name, call := range map[string]func() error{
			"ref": func() error {
				_, err := newAzureWorkloadIdentityTokenSource(context.Background(), nil, validIdentity, requester, nil)
				return err
			},
			"identity": func() error {
				_, err := newAzureWorkloadIdentityTokenSource(context.Background(), validRef, nil, requester, nil)
				return err
			},
			"requester": func() error {
				_, err := newAzureWorkloadIdentityTokenSource(context.Background(), validRef, validIdentity, nil, nil)
				return err
			},
		} {
			t.Run(name, func(t *testing.T) {
				err := call()
				require.Error(t, err)
				assert.ErrorIs(t, err, errInvalidConfig)
			})
		}
		assert.Empty(t, requester.calls)
	})

	// The tenant ID becomes part of the login URL path. The SDK must reject anything that could
	// alter that path, and no ServiceAccount token may be minted before it does.
	for _, tenant := range []string{"", "../other", "tenant/evil", "tenant?x=y", "tenant#frag", "ten ant", "tenant\n"} {
		t.Run("rejects-tenant-"+tenant, func(t *testing.T) {
			requester := &fakeTokenRequester{token: "t"}

			src, err := newAzureWorkloadIdentityTokenSource(context.Background(), validRef,
				&AzureIdentity{ClientID: "client", TenantID: tenant}, requester, []string{"scope"})

			require.Error(t, err)
			assert.ErrorIs(t, err, errTokenFetchFailure)
			assert.Nil(t, src)
			assert.Empty(t, requester.calls, "no token may be requested for an invalid identity")
		})
	}
}

func TestAzureTokenSourceFromCredential(t *testing.T) {
	expiry := time.Now().Add(time.Hour)

	t.Run("returns-the-credential-token-as-a-bearer-token", func(t *testing.T) {
		cred := &fakeAzureCredential{token: azcore.AccessToken{Token: "access-token", ExpiresOn: expiry}}

		src, err := newAzureTokenSourceFromCredential(context.Background(), cred, "WorkloadIdentityCredential", []string{"api://x/.default"})
		require.NoError(t, err)
		token, err := src.Token()

		require.NoError(t, err)
		assert.Equal(t, "access-token", token.AccessToken)
		assert.Equal(t, "Bearer", token.TokenType)
		assert.True(t, expiry.Equal(token.Expiry))
		assert.Equal(t, []string{"api://x/.default"}, cred.opts.Scopes)
	})

	t.Run("fails-fast-and-names-the-credential", func(t *testing.T) {
		cred := &fakeAzureCredential{err: errors.New("AADSTS70021: no matching federated identity record")}

		src, err := newAzureTokenSourceFromCredential(context.Background(), cred, "WorkloadIdentityCredential", nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, errTokenFetchFailure)
		assert.Contains(t, err.Error(), "WorkloadIdentityCredential")
		assert.Contains(t, err.Error(), "AADSTS70021")
		assert.Nil(t, src)
	})

	t.Run("default-credential-name-is-kept-for-existing-behavior", func(t *testing.T) {
		cred := &fakeAzureCredential{err: errors.New("boom")}

		_, err := newAzureTokenSourceFromCredential(context.Background(), cred, "DefaultAzureCredential", nil)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch token from Azure DefaultAzureCredential")
	})

	t.Run("debug-logging-labels-the-credential-and-never-prints-the-raw-token", func(t *testing.T) {
		accessToken := createUnsignedJWT(t, jwt.MapClaims{
			"aud": "api://command", "appid": "client", "iss": "https://sts.windows.net/tenant/", "sub": "subject", "oid": "object",
		})
		cred := &fakeAzureCredential{token: azcore.AccessToken{Token: accessToken, ExpiresOn: expiry}}

		var buf bytes.Buffer
		logger := funcr.New(func(prefix, args string) { buf.WriteString(prefix + args + "\n") }, funcr.Options{})
		ctx := logr.NewContext(context.Background(), logger)

		_, err := newAzureTokenSourceFromCredential(ctx, cred, "WorkloadIdentityCredential", nil)
		require.NoError(t, err)

		logs := buf.String()
		assert.Contains(t, logs, "BEGIN DEBUG: WorkloadIdentityCredential JWT")
		assert.Contains(t, logs, "END DEBUG: WorkloadIdentityCredential JWT")
		assert.NotContains(t, logs, accessToken, "the raw token must never be logged")
	})
}

func TestNewAzureWorkloadIdentityTokenSourceWiring(t *testing.T) {
	type captured struct {
		tenantID, clientID string
		getAssertion       func(context.Context) (string, error)
	}

	install := func(t *testing.T, cred azcore.TokenCredential) *captured {
		t.Helper()
		got := &captured{}
		original := newAzureAssertionCredential
		newAzureAssertionCredential = func(tenantID, clientID string, getAssertion func(context.Context) (string, error)) (azcore.TokenCredential, error) {
			got.tenantID, got.clientID, got.getAssertion = tenantID, clientID, getAssertion
			return cred, nil
		}
		t.Cleanup(func() { newAzureAssertionCredential = original })
		return got
	}

	t.Run("uses-the-resolved-identity-and-asserts-as-the-referenced-serviceaccount", func(t *testing.T) {
		cred := &fakeAzureCredential{token: azcore.AccessToken{Token: "access-token", ExpiresOn: time.Now().Add(time.Hour)}}
		got := install(t, cred)
		requester := &fakeTokenRequester{token: "sa-token"}

		src, err := newAzureWorkloadIdentityTokenSource(context.Background(),
			&ServiceAccountRef{Name: "sa-a", Namespace: "tenant-a"},
			&AzureIdentity{ClientID: "client-a", TenantID: "tenant-id-a"}, requester, []string{"api://x/.default"})

		require.NoError(t, err)
		assert.Equal(t, "client-a", got.clientID)
		assert.Equal(t, "tenant-id-a", got.tenantID)

		_, err = got.getAssertion(context.Background())
		require.NoError(t, err)
		require.Len(t, requester.calls, 1)
		assert.Equal(t, "tenant-a", requester.calls[0].namespace)
		assert.Equal(t, "sa-a", requester.calls[0].name)

		token, err := src.Token()
		require.NoError(t, err)
		assert.Equal(t, "access-token", token.AccessToken)
		assert.Equal(t, []string{"api://x/.default"}, cred.opts.Scopes)
	})

	t.Run("two-sources-keep-separate-identities", func(t *testing.T) {
		var tenants []string
		original := newAzureAssertionCredential
		newAzureAssertionCredential = func(tenantID, clientID string, getAssertion func(context.Context) (string, error)) (azcore.TokenCredential, error) {
			tenants = append(tenants, tenantID+"/"+clientID)
			return &fakeAzureCredential{token: azcore.AccessToken{Token: clientID, ExpiresOn: time.Now().Add(time.Hour)}}, nil
		}
		t.Cleanup(func() { newAzureAssertionCredential = original })
		requester := &fakeTokenRequester{token: "t"}

		a, err := newAzureWorkloadIdentityTokenSource(context.Background(), &ServiceAccountRef{Name: "sa-a", Namespace: "tenant-a"}, &AzureIdentity{ClientID: "client-a", TenantID: "t1"}, requester, nil)
		require.NoError(t, err)
		b, err := newAzureWorkloadIdentityTokenSource(context.Background(), &ServiceAccountRef{Name: "sa-b", Namespace: "tenant-b"}, &AzureIdentity{ClientID: "client-b", TenantID: "t2"}, requester, nil)
		require.NoError(t, err)

		tokenA, err := a.Token()
		require.NoError(t, err)
		tokenB, err := b.Token()
		require.NoError(t, err)
		assert.Equal(t, "client-a", tokenA.AccessToken)
		assert.Equal(t, "client-b", tokenB.AccessToken)
		assert.Equal(t, []string{"t1/client-a", "t2/client-b"}, tenants)
	})

	t.Run("credential-construction-error-is-wrapped", func(t *testing.T) {
		original := newAzureAssertionCredential
		boom := errors.New("bad tenant")
		newAzureAssertionCredential = func(string, string, func(context.Context) (string, error)) (azcore.TokenCredential, error) {
			return nil, boom
		}
		t.Cleanup(func() { newAzureAssertionCredential = original })

		src, err := newAzureWorkloadIdentityTokenSource(context.Background(), &ServiceAccountRef{Name: "sa", Namespace: "ns"}, &AzureIdentity{ClientID: "c", TenantID: "t"}, &fakeTokenRequester{}, nil)

		require.Error(t, err)
		assert.ErrorIs(t, err, errTokenFetchFailure)
		assert.ErrorIs(t, err, boom)
		assert.Nil(t, src)
	})
}
