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

	"github.com/go-logr/logr/testr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestPrintClaims(t *testing.T) {
	testLogger := testr.New(t)
	t.Run("valid jwt returns no error", func(t *testing.T) {
		// Sample JWT with dummy claims (no signature needed for ParseUnverified)
		claims := jwt.MapClaims{
			"aud": "api://1234",
			"iss": "https://sts.windows.net/tenant-id/",
			"sub": "user-id",
		}
		token := createUnsignedJWT(t, claims)

		// Call the function
		err := printClaims(testLogger, token, []string{"aud", "iss", "sub"})
		assert.NoError(t, err)
	})

	t.Run("jwt with no issuer does not error", func(t *testing.T) {
		// Sample JWT with dummy claims (no signature needed for ParseUnverified)
		claims := jwt.MapClaims{
			"aud": "api://1234",
			"sub": "user-id",
		}
		token := createUnsignedJWT(t, claims)

		// Call the function
		err := printClaims(testLogger, token, []string{"aud", "iss", "sub"})
		assert.NoError(t, err)
	})

	t.Run("jwt with empty claims does not error", func(t *testing.T) {
		// Sample JWT with dummy claims (no signature needed for ParseUnverified)
		claims := jwt.MapClaims{}
		token := createUnsignedJWT(t, claims)

		// Call the function
		err := printClaims(testLogger, token, []string{"aud", "iss", "sub"})
		assert.NoError(t, err)
	})

	t.Run("invalid jwt returns an error", func(t *testing.T) {
		// Call the function
		err := printClaims(testLogger, "abcdefghijklmnop", []string{"aud", "iss", "sub"})
		assert.Error(t, err)
	})

	t.Run("jwt with empty payload returns error", func(t *testing.T) {
		// Call the function
		err := printClaims(testLogger, "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0..", []string{"aud", "iss", "sub"})
		assert.Error(t, err)
	})
}

func createUnsignedJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()

	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	str, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("failed to create test token: %v", err)
	}
	return str
}
