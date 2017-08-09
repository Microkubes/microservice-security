package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"

	"net/http/httptest"

	"golang.org/x/net/context"

	"github.com/JormungandrK/microservice-security/auth"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
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
