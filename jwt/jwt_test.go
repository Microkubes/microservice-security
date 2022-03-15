package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"net/http/httptest"

	"context"

	"github.com/Microkubes/microservice-security/auth"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/keitaroinc/goa"
	goajwt "github.com/keitaroinc/goa/middleware/security/jwt"
)

func TestJWTMiddleware(t *testing.T) {
	resolver, key, err := newResolverAndKey()
	if err != nil {
		t.Fatal(err)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"username":      "test-user",
		"userId":        "f77fc7b6-faa4-4c64-b18c-934ba3f913dd",
		"roles":         "user",
		"organizations": "Org1,Org2",
	})

	tokenStr, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(tokenStr)
	req := httptest.NewRequest("GET", "http://example.com", nil)
	req.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", tokenStr)}

	middleware := NewJWTSecurityMiddleware(*resolver, &goa.JWTSecurity{
		Description: "Test JWT Security",
		In:          goa.LocHeader,
		Name:        "Authorization",
		Scopes: map[string]string{
			"api:read":  "Read access to the API",
			"api:write": "Write access to the API",
		},
		TokenURL: "http://issuer.jwt",
	})

	ctx, _, err := middleware(context.Background(), nil, req)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(auth.GetAuth(ctx))
}

func generateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func newResolverAndKey() (*goajwt.KeyResolver, *rsa.PrivateKey, error) {
	key, err := generateRSAKeyPair()
	if err != nil {
		return nil, nil, err
	}
	keys := []goajwt.Key{}
	keys = append(keys, &key.PublicKey)
	println(len(keys))
	resolver := goajwt.NewSimpleResolver(keys)
	return &resolver, key, nil
}

func generateRSAKeyPairInDir(dir string, keyFileName string) error {
	keyPair, err := generateRSAKeyPair()
	if err != nil {
		return err
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey) //asn1.Marshal(keyPair.PublicKey)

	if err != nil {
		return err
	}

	pubPemKey := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	privPemKey := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}

	pubKeyFile, err := os.Create(fmt.Sprintf("%s/%s.pub", dir, keyFileName))
	if err != nil {
		return err
	}
	privKeyFile, err := os.Create(fmt.Sprintf("%s/%s", dir, keyFileName))
	if err != nil {
		return err
	}

	err = pem.Encode(pubKeyFile, pubPemKey)
	if err != nil {
		return err
	}
	err = pem.Encode(privKeyFile, privPemKey)
	if err != nil {
		return err
	}

	return nil
}

func TestNewKeyResolver(t *testing.T) {
	keysDir, err := ioutil.TempDir("", "keys")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Keys will be saved in: ", keysDir)
	defer os.RemoveAll(keysDir)

	err = generateRSAKeyPairInDir(keysDir, "test_key")

	if err != nil {
		t.Fatal(err)
	}

	// create the resolver with keys directory
	resolver, err := NewKeyResolver(keysDir)

	if err != nil {
		t.Fatal(err)
	}

	keys := resolver.SelectKeys(httptest.NewRequest("GET", "http://example.com", nil))
	if keys == nil {
		t.Fatal("Expected keys array")
	}
	if len(keys) == 0 || keys[0] == nil {
		t.Fatal("Expected at least one key")
	}
}

func TestNewJWTSecurity(t *testing.T) {
	keysDir, err := ioutil.TempDir("", "keys")
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Keys will be saved in: ", keysDir)
	defer os.RemoveAll(keysDir)

	err = generateRSAKeyPairInDir(keysDir, "test_key")

	if err != nil {
		t.Fatal(err)
	}

	middleware := NewJWTSecurity(keysDir, &goa.JWTSecurity{
		Description: "Test JWT Security",
		In:          goa.LocHeader,
		Name:        "Authorization",
		Scopes: map[string]string{
			"api:read":  "Read access to the API",
			"api:write": "Write access to the API",
		},
		TokenURL: "http://issuer.jwt",
	})
	if middleware == nil {
		t.Fatal("Expected JWT middleware to be created")
	}

}
