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
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"

	commandsdk "github.com/Keyfactor/keyfactor-go-client-sdk/v25"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// ClientCache provides thread-safe caching of Command API clients to avoid
// re-authenticating (and fetching new OAuth tokens) for every request.
// Clients are cached by a hash of their configuration, so different issuers
// with different configs get different clients, but the same issuer reuses
// its client across reconciliations.
type ClientCache struct {
	mu      sync.RWMutex
	clients map[string]*cachedClient
}

type cachedClient struct {
	signer *signer
}

// NewClientCache creates a new ClientCache instance.
func NewClientCache() *ClientCache {
	return &ClientCache{
		clients: make(map[string]*cachedClient),
	}
}

// configHash generates a unique hash for a Config to use as a cache key.
// This ensures that different configurations get different clients.
func configHash(config *Config) string {
	h := sha256.New()

	// Include all fields that affect the client connection
	h.Write([]byte(config.Hostname))
	h.Write([]byte(config.APIPath))
	h.Write(config.CaCertsBytes)

	if config.BasicAuth != nil {
		h.Write([]byte("basic"))
		h.Write([]byte(config.BasicAuth.Username))
		h.Write([]byte(config.BasicAuth.Password))
	}

	if config.OAuth != nil {
		h.Write([]byte("oauth"))
		h.Write([]byte(config.OAuth.TokenURL))
		h.Write([]byte(config.OAuth.ClientID))
		h.Write([]byte(config.OAuth.ClientSecret))
		h.Write([]byte(config.OAuth.Audience))
		for _, scope := range config.OAuth.Scopes {
			h.Write([]byte(scope))
		}
	}

	// Include ambient credential config
	h.Write([]byte(config.AmbientCredentialAudience))
	for _, scope := range config.AmbientCredentialScopes {
		h.Write([]byte(scope))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// GetOrCreateSigner returns a cached signer for the given config, or creates
// a new one if none exists. This ensures OAuth tokens are reused across
// requests to the same Command instance.
func (c *ClientCache) GetOrCreateSigner(ctx context.Context, config *Config) (Signer, error) {
	key := configHash(config)
	logger := log.FromContext(ctx)

	// Fast path: check if we have a cached client
	c.mu.RLock()
	if cached, ok := c.clients[key]; ok {
		c.mu.RUnlock()
		logger.V(1).Info("Reusing cached Command client", "cacheKey", key[:12])
		return cached.signer, nil
	}
	c.mu.RUnlock()

	// Slow path: create a new client
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := c.clients[key]; ok {
		logger.V(1).Info("Reusing cached Command client (after lock)", "cacheKey", key[:12])
		return cached.signer, nil
	}

	logger.Info("Creating new Command client (will be cached for future requests)", "cacheKey", key[:12])

	s, err := newInternalSigner(ctx, config, commandsdk.NewAPIClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer: %w", err)
	}

	c.clients[key] = &cachedClient{signer: s}
	return s, nil
}

// GetOrCreateHealthChecker returns a cached health checker for the given config.
// Since the signer type implements both Signer and HealthChecker interfaces,
// this shares the same cache as GetOrCreateSigner.
func (c *ClientCache) GetOrCreateHealthChecker(ctx context.Context, config *Config) (HealthChecker, error) {
	key := configHash(config)
	logger := log.FromContext(ctx)

	// Fast path: check if we have a cached client
	c.mu.RLock()
	if cached, ok := c.clients[key]; ok {
		c.mu.RUnlock()
		logger.V(1).Info("Reusing cached Command client for health check", "cacheKey", key[:12])
		return cached.signer, nil
	}
	c.mu.RUnlock()

	// Slow path: create a new client
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, ok := c.clients[key]; ok {
		logger.V(1).Info("Reusing cached Command client for health check (after lock)", "cacheKey", key[:12])
		return cached.signer, nil
	}

	logger.Info("Creating new Command client for health check (will be cached)", "cacheKey", key[:12])

	s, err := newInternalSigner(ctx, config, commandsdk.NewAPIClient)
	if err != nil {
		return nil, fmt.Errorf("failed to create health checker: %w", err)
	}

	c.clients[key] = &cachedClient{signer: s}
	return s, nil
}

// Invalidate removes a cached client for the given config.
// This should be called when an issuer's credentials are updated.
func (c *ClientCache) Invalidate(config *Config) {
	key := configHash(config)
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.clients, key)
}

// InvalidateAll removes all cached clients.
// This can be used during shutdown or when a global credential refresh is needed.
func (c *ClientCache) InvalidateAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients = make(map[string]*cachedClient)
}

// Size returns the number of cached clients.
func (c *ClientCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.clients)
}
