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
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Keyfactor/keyfactor-auth-client-go/auth_providers"
	v1 "github.com/Keyfactor/keyfactor-go-client-sdk/v25/api/keyfactor/v1"
	"github.com/go-logr/logr"
)

/*
This utility provides diagnostic-only network tracing, enabled by the environment variable
"COMMAND_ISSUER_HTTP_TRACE=true" or "COMMAND_ISSUER_HTTP_TRACE=1" on the controller. When enabled,
every outbound Command HTTP request emits one structured "http trace" log line
describing how the connection was obtained and where the time went.

Request behavior is unaffected.
*/

const EnvHTTPTrace = "COMMAND_ISSUER_HTTP_TRACE"

func httpTraceEnabled() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(EnvHTTPTrace)))
	return v == "true" || v == "1"
}

// Wraps the AuthClient on a freshly build SDK client so that all SDK requests and healthcheck
// are traced.
func enableHTTPTrace(client v1.AuthConfig, server *auth_providers.Server, logger logr.Logger) v1.AuthConfig {
	return &tracingAuthConfig{inner: client, server: server, logger: logger.WithName("httptrace")}
}

// Thin wrapper around the AuthConfig that attaches HTTP tracing to each request.
// It implements the v1.AuthConfig interface and delegates all calls to the inner AuthConfig,
// adding HTTP tracing to the HTTP client returned by GetHttpClient().
type tracingAuthConfig struct {
	inner  v1.AuthConfig
	server *auth_providers.Server
	logger logr.Logger
}

var _ v1.AuthConfig = &tracingAuthConfig{}

func (t *tracingAuthConfig) GetServerConfig() *auth_providers.Server {
	return t.inner.GetServerConfig()
}

func (t *tracingAuthConfig) GetHttpClient() (*http.Client, error) {
	hc, err := t.inner.GetHttpClient()
	if err != nil {
		return nil, err
	}
	hc.Transport = &traceTransport{base: hc.Transport, logger: t.logger}
	return hc, nil
}

// Mirrors the auth_provider.CommandAuthConfig.Authenticate method by performing
// the same HTTP GET request to the Status/Endpoints endpoint. The upstream implementation
// builds its own client internally, which leaves no hook for tracing.
// TODO: Revalidate this behavior when keyfactor-auth-client-go is bumped.
func (t *tracingAuthConfig) Authenticate() error {
	hc, err := t.GetHttpClient()
	if err != nil {
		return err
	}
	if t.server.ClientTimeout > 0 {
		hc.Timeout = time.Duration(t.server.ClientTimeout) * time.Second
	}

	endpoint := fmt.Sprintf("%s://%s/%s/Status/Endpoints", auth_providers.DefaultHttpProtocol, t.server.Host, t.server.APIPath)
	req, err := http.NewRequest(http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("x-keyfactor-api-version", auth_providers.DefaultAPIVersion)
	req.Header.Set("x-keyfactor-requested-with", auth_providers.DefaultAPIClientName)

	resp, err := hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to authenticate, received status code %d from Keyfactor Command: %s", resp.StatusCode, string(body))
	}
	return nil
}

// traceTransport attaches an httptrace.ClientTrace to each request and logs a
// single summary line when the round trip finishes.
type traceTransport struct {
	base   http.RoundTripper
	logger logr.Logger
}

func (t *traceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := &traceRecord{start: time.Now()}
	trace := rec.clientTrace()
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	proxy := "none"
	if u, err := http.ProxyFromEnvironment(req); err == nil && u != nil {
		proxy = u.Host // host only; never log userinfo
	}

	resp, err := t.base.RoundTrip(req)
	t.logger.Info("http trace", rec.fields(req, proxy, resp, err)...)
	return resp, err
}

type connInfo struct {
	reused, wasIdle bool
	idleTime        time.Duration
	local, remote   string
	at              time.Duration
}

// traceRecord collects events for one RoundTrip. httptrace callbacks can fire
// from goroutines other than the caller's (dial), hence the mutex.
type traceRecord struct {
	mu    sync.Mutex
	start time.Time

	conns                                 []connInfo
	dnsStart, dnsDone                     time.Time
	connectStart, connectDone             time.Time
	connectAddr                           string
	connectErr                            error
	tlsStart, tlsDone                     time.Time
	tlsErr                                error
	wroteHeaders, wroteRequest, firstByte time.Time
	wroteErr                              error
}

func (r *traceRecord) clientTrace() *httptrace.ClientTrace {
	now := time.Now
	return &httptrace.ClientTrace{
		GotConn: func(i httptrace.GotConnInfo) {
			r.mu.Lock()
			defer r.mu.Unlock()
			c := connInfo{reused: i.Reused, wasIdle: i.WasIdle, idleTime: i.IdleTime, at: time.Since(r.start)}
			if i.Conn != nil {
				c.local = i.Conn.LocalAddr().String()
				c.remote = i.Conn.RemoteAddr().String()
			}
			r.conns = append(r.conns, c)
		},
		DNSStart: func(httptrace.DNSStartInfo) { r.mu.Lock(); r.dnsStart = now(); r.mu.Unlock() },
		DNSDone:  func(httptrace.DNSDoneInfo) { r.mu.Lock(); r.dnsDone = now(); r.mu.Unlock() },
		ConnectStart: func(_, addr string) {
			r.mu.Lock()
			r.connectStart, r.connectAddr = now(), addr
			r.mu.Unlock()
		},
		ConnectDone: func(_, _ string, err error) {
			r.mu.Lock()
			r.connectDone, r.connectErr = now(), err
			r.mu.Unlock()
		},
		TLSHandshakeStart: func() { r.mu.Lock(); r.tlsStart = now(); r.mu.Unlock() },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			r.mu.Lock()
			r.tlsDone, r.tlsErr = now(), err
			r.mu.Unlock()
		},
		WroteHeaders: func() { r.mu.Lock(); r.wroteHeaders = now(); r.mu.Unlock() },
		WroteRequest: func(i httptrace.WroteRequestInfo) {
			r.mu.Lock()
			r.wroteRequest, r.wroteErr = now(), i.Err
			r.mu.Unlock()
		},
		GotFirstResponseByte: func() { r.mu.Lock(); r.firstByte = now(); r.mu.Unlock() },
	}
}

func (r *traceRecord) span(from, to time.Time) string {
	if from.IsZero() || to.IsZero() {
		return "n/a"
	}
	return to.Sub(from).Round(time.Millisecond).String()
}

// stage reports the last stage the request reached, which for a failed
// request identifies the phase in which the peer (or a middlebox) dropped it.
func (r *traceRecord) stage() string {
	switch {
	case r.connectErr != nil:
		return "tcp-connect-failed"
	case r.tlsErr != nil:
		return "tls-handshake-failed"
	case !r.firstByte.IsZero():
		return "response-received"
	case !r.wroteRequest.IsZero():
		return "request-written-awaiting-response"
	case len(r.conns) > 0:
		return "got-conn-writing-request"
	case !r.tlsStart.IsZero() && r.tlsDone.IsZero():
		return "tls-handshake"
	case !r.tlsDone.IsZero():
		return "tls-done-before-got-conn"
	case !r.connectStart.IsZero() && r.connectDone.IsZero():
		return "tcp-connect"
	case !r.dnsStart.IsZero() && r.dnsDone.IsZero():
		return "dns"
	default:
		return "before-dial"
	}
}

func (r *traceRecord) fields(req *http.Request, proxy string, resp *http.Response, err error) []any {
	r.mu.Lock()
	defer r.mu.Unlock()

	u := req.URL.Host + req.URL.Path // no scheme, query, or userinfo
	f := []any{
		"method", req.Method,
		"url", u,
		"proxy", proxy,
		// More than one entry means net/http transparently retried the request
		// on another connection after the first failed.
		"gotConnCount", len(r.conns),
		"total", time.Since(r.start).Round(time.Millisecond).String(),
		"dns", r.span(r.dnsStart, r.dnsDone),
		"tcpConnect", r.span(r.connectStart, r.connectDone),
		"connectAddr", r.connectAddr,
		"tlsHandshake", r.span(r.tlsStart, r.tlsDone),
		"timeToFirstByte", r.span(r.wroteRequest, r.firstByte),
		"stage", r.stage(),
	}
	for i, c := range r.conns {
		p := fmt.Sprintf("conn%d.", i+1)
		f = append(f,
			p+"reused", c.reused,
			p+"wasIdle", c.wasIdle,
			p+"idleTime", c.idleTime.Round(time.Millisecond).String(),
			p+"local", c.local,
			p+"remote", c.remote,
			p+"atOffset", c.at.Round(time.Millisecond).String(),
		)
	}
	if r.connectErr != nil {
		f = append(f, "connectErr", r.connectErr.Error())
	}
	if r.tlsErr != nil {
		f = append(f, "tlsErr", r.tlsErr.Error())
	}
	if r.wroteErr != nil {
		f = append(f, "wroteErr", r.wroteErr.Error())
	}
	if resp != nil {
		f = append(f, "status", resp.StatusCode)
	}
	if err != nil {
		f = append(f,
			"error", err.Error(),
			"isEOF", errors.Is(err, io.EOF),
			"isUnexpectedEOF", errors.Is(err, io.ErrUnexpectedEOF),
		)
	}
	return f
}
