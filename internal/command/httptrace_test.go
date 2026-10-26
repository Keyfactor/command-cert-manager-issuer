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
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	commandsdk "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/go-logr/logr/funcr"
	"github.com/stretchr/testify/require"
)

type lineSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *lineSink) add(prefix, args string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, prefix+" "+args)
}

func newTraceServer(t *testing.T, newConns *int) *httptest.Server {
	var mu sync.Mutex
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			mu.Lock()
			*newConns++
			mu.Unlock()
		}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func TestHTTPTrace_LogsHealthCheckAndSDKRequests(t *testing.T) {
	servers := map[string]func(host string) *auth_providers.Server{
		"basic": func(host string) *auth_providers.Server {
			return &auth_providers.Server{Host: host, APIPath: "KeyfactorAPI", AuthType: "basic", Username: "u", Password: "p", SkipTLSVerify: true}
		},
		"oauth-access-token": func(host string) *auth_providers.Server {
			return &auth_providers.Server{Host: host, APIPath: "KeyfactorAPI", AuthType: "oauth", AccessToken: "tok", SkipTLSVerify: true}
		},
	}
	for name, mk := range servers {
		t.Run(name, func(t *testing.T) {
			var newConns int
			srv := newTraceServer(t, &newConns)
			cfg := mk(strings.TrimPrefix(srv.URL, "https://"))

			client, err := commandsdk.NewAPIClient(cfg)
			require.NoError(t, err)

			sink := &lineSink{}
			logger := funcr.New(sink.add, funcr.Options{})
			client.AuthClient = enableHTTPTrace(client.AuthClient, cfg, logger)

			require.NoError(t, client.AuthClient.Authenticate())
			_, resp, err := client.MetadataFieldApi.GetMetadataFieldsExecute(commandsdk.ApiGetMetadataFieldsRequest{})
			require.NoError(t, err)
			_ = resp.Body.Close()

			require.Len(t, sink.lines, 2)
			require.Contains(t, sink.lines[0], `"url"="`+cfg.Host+`/KeyfactorAPI/Status/Endpoints"`)
			require.Contains(t, sink.lines[1], "MetadataFields")
			for _, l := range sink.lines {
				require.Contains(t, l, `"conn1.reused"=false`)
				require.Contains(t, l, `"conn1.local"="127.0.0.1:`)
				require.Contains(t, l, `"conn1.remote"="127.0.0.1:`)
				require.Contains(t, l, `"status"=200`)
				require.Contains(t, l, `"stage"="response-received"`)
				require.NotContains(t, l, "tok")
			}
			// Documents the dependency behavior this diagnostic is investigating: the
			// auth client builds a new transport per call, so no connection is reused.
			require.Equal(t, 3, newConns, "1 at construction + 1 per traced request")
		})
	}
}

func TestHTTPTrace_RecordsEOF(t *testing.T) {
	// A server that accepts TCP and closes immediately simulates a middlebox dropping a new tunnel.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	sink := &lineSink{}
	cfg := &auth_providers.Server{Host: ln.Addr().String(), APIPath: "KeyfactorAPI", AuthType: "basic", Username: "u", Password: "p", SkipTLSVerify: true}
	ta := &tracingAuthConfig{inner: &fakeAuth{cfg: cfg}, server: cfg, logger: funcr.New(sink.add, funcr.Options{})}

	require.Error(t, ta.Authenticate())
	require.Len(t, sink.lines, 1)
	require.Contains(t, sink.lines[0], `"stage"="tls-handshake-failed"`)
	require.Contains(t, sink.lines[0], `"isEOF"=true`)
}

func TestHTTPTrace_httpTraceEnabled(t *testing.T) {
	t.Run("enabled with true", func(t *testing.T) {
		os.Setenv(EnvHTTPTrace, "true")
		defer os.Unsetenv(EnvHTTPTrace)
		require.True(t, httpTraceEnabled())
	})
	t.Run("enabled with 1", func(t *testing.T) {
		os.Setenv(EnvHTTPTrace, "1")
		defer os.Unsetenv(EnvHTTPTrace)
		require.True(t, httpTraceEnabled())
	})
	t.Run("disabled with false", func(t *testing.T) {
		os.Setenv(EnvHTTPTrace, "false")
		defer os.Unsetenv(EnvHTTPTrace)
		require.False(t, httpTraceEnabled())
	})
	t.Run("disabled with 0", func(t *testing.T) {
		os.Setenv(EnvHTTPTrace, "0")
		defer os.Unsetenv(EnvHTTPTrace)
		require.False(t, httpTraceEnabled())
	})
	t.Run("disabled with empty", func(t *testing.T) {
		os.Unsetenv(EnvHTTPTrace)
		require.False(t, httpTraceEnabled())
	})
}

type fakeAuth struct{ cfg *auth_providers.Server }

func (f *fakeAuth) Authenticate() error                     { return nil }
func (f *fakeAuth) GetServerConfig() *auth_providers.Server { return f.cfg }
func (f *fakeAuth) GetHttpClient() (*http.Client, error) {
	b := &auth_providers.CommandAuthConfig{SkipVerify: true}
	tr, err := b.BuildTransport()
	return &http.Client{Transport: tr}, err
}
