package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestSignToken(t *testing.T) {
	keyPair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]interface{}{
		"exp":           1502897618,
		"iat":           1502897588,
		"iss":           "Jormungandr JWT Authority",
		"jti":           "1eaca8d8-8cdf-4cb8-b20c-6234d2dca5de",
		"nbf":           0,
		"organizations": "org1,org2",
		"roles":         "user",
		"scopes":        "api:read",
		"sub":           "59941c5d0000000000000000",
		"userId":        "59941c5d0000000000000000",
		"username":      "test-user",
	}

	token, err := SignToken(claims, "RS512", keyPair)

	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("Expected JWT token, not empty string")
	}
}
