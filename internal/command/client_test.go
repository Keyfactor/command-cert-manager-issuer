package command

import (
	"testing"

	"github.com/go-logr/logr/testr"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestPrintClaims(t *testing.T) {
	t.Run("valid jwt returns no error", func(t *testing.T) {
		// Sample JWT with dummy claims (no signature needed for ParseUnverified)
		claims := jwt.MapClaims{
			"aud": "api://1234",
			"iss": "https://sts.windows.net/tenant-id/",
			"sub": "user-id",
		}
		token := createUnsignedJWT(t, claims)

		// Use testr logger
		testLogger := testr.New(t)

		// Call the function
		err := printClaims(testLogger, token, []string{"aud", "iss", "sub"})
		assert.NoError(t, err)
	})

	t.Run("invalid jwt returns an error", func(t *testing.T) {
		// Use testr logger
		testLogger := testr.New(t)

		// Call the function
		err := printClaims(testLogger, "abcdefghijklmnop", []string{"aud", "iss", "sub"})
		assert.Error(t, err)
	})

	t.Run("jwt with no claims returns error", func(t *testing.T) {
		// Use testr logger
		testLogger := testr.New(t)

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
