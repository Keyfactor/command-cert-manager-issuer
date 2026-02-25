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
	"testing"
)

func TestConfigHash(t *testing.T) {
	tests := []struct {
		name     string
		config1  *Config
		config2  *Config
		wantSame bool
	}{
		{
			name: "identical configs produce same hash",
			config1: &Config{
				Hostname: "test.example.com",
				APIPath:  "KeyfactorAPI",
				OAuth: &OAuth{
					TokenURL:     "https://auth.example.com/token",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
			},
			config2: &Config{
				Hostname: "test.example.com",
				APIPath:  "KeyfactorAPI",
				OAuth: &OAuth{
					TokenURL:     "https://auth.example.com/token",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
			},
			wantSame: true,
		},
		{
			name: "different hostnames produce different hash",
			config1: &Config{
				Hostname: "test1.example.com",
				APIPath:  "KeyfactorAPI",
			},
			config2: &Config{
				Hostname: "test2.example.com",
				APIPath:  "KeyfactorAPI",
			},
			wantSame: false,
		},
		{
			name: "different OAuth credentials produce different hash",
			config1: &Config{
				Hostname: "test.example.com",
				APIPath:  "KeyfactorAPI",
				OAuth: &OAuth{
					TokenURL:     "https://auth.example.com/token",
					ClientID:     "client-id-1",
					ClientSecret: "client-secret",
				},
			},
			config2: &Config{
				Hostname: "test.example.com",
				APIPath:  "KeyfactorAPI",
				OAuth: &OAuth{
					TokenURL:     "https://auth.example.com/token",
					ClientID:     "client-id-2",
					ClientSecret: "client-secret",
				},
			},
			wantSame: false,
		},
		{
			name: "basic auth vs oauth produce different hash",
			config1: &Config{
				Hostname: "test.example.com",
				APIPath:  "KeyfactorAPI",
				BasicAuth: &BasicAuth{
					Username: "user",
					Password: "pass",
				},
			},
			config2: &Config{
				Hostname: "test.example.com",
				APIPath:  "KeyfactorAPI",
				OAuth: &OAuth{
					TokenURL:     "https://auth.example.com/token",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
				},
			},
			wantSame: false,
		},
		{
			name: "different scopes produce different hash",
			config1: &Config{
				Hostname: "test.example.com",
				APIPath:  "KeyfactorAPI",
				OAuth: &OAuth{
					TokenURL:     "https://auth.example.com/token",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					Scopes:       []string{"scope1"},
				},
			},
			config2: &Config{
				Hostname: "test.example.com",
				APIPath:  "KeyfactorAPI",
				OAuth: &OAuth{
					TokenURL:     "https://auth.example.com/token",
					ClientID:     "client-id",
					ClientSecret: "client-secret",
					Scopes:       []string{"scope1", "scope2"},
				},
			},
			wantSame: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := configHash(tt.config1)
			hash2 := configHash(tt.config2)

			if tt.wantSame && hash1 != hash2 {
				t.Errorf("expected same hash, got different: %s vs %s", hash1, hash2)
			}
			if !tt.wantSame && hash1 == hash2 {
				t.Errorf("expected different hash, got same: %s", hash1)
			}
		})
	}
}

func TestClientCache_BasicOperations(t *testing.T) {
	cache := NewClientCache()

	// Initial size should be 0
	if cache.Size() != 0 {
		t.Errorf("expected empty cache, got size %d", cache.Size())
	}

	// After invalidating a non-existent config, size should still be 0
	cache.Invalidate(&Config{Hostname: "test.example.com"})
	if cache.Size() != 0 {
		t.Errorf("expected empty cache after invalidating non-existent, got size %d", cache.Size())
	}

	// InvalidateAll on empty cache should work
	cache.InvalidateAll()
	if cache.Size() != 0 {
		t.Errorf("expected empty cache after InvalidateAll, got size %d", cache.Size())
	}
}

func TestConfigHash_Deterministic(t *testing.T) {
	config := &Config{
		Hostname: "test.example.com",
		APIPath:  "KeyfactorAPI",
		OAuth: &OAuth{
			TokenURL:     "https://auth.example.com/token",
			ClientID:     "client-id",
			ClientSecret: "client-secret",
			Scopes:       []string{"scope1", "scope2"},
			Audience:     "audience",
		},
		CaCertsBytes:              []byte("ca-cert-data"),
		AmbientCredentialAudience: "ambient-audience",
		AmbientCredentialScopes:   []string{"ambient-scope"},
	}

	// Hash should be deterministic
	hash1 := configHash(config)
	hash2 := configHash(config)
	hash3 := configHash(config)

	if hash1 != hash2 || hash2 != hash3 {
		t.Errorf("hash is not deterministic: %s, %s, %s", hash1, hash2, hash3)
	}

	// Hash should be a valid hex string of expected length (SHA-256 = 64 hex chars)
	if len(hash1) != 64 {
		t.Errorf("expected hash length 64, got %d", len(hash1))
	}
}
