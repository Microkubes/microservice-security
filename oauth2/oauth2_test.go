package oauth2

// import (
// 	"context"
// 	"crypto/ecdsa"
// 	"crypto/elliptic"
// 	"crypto/rand"
// 	"crypto/rsa"
// 	"crypto/x509"
// 	"encoding/pem"
// 	"fmt"
// 	"io/ioutil"
// 	"net/http"
// 	"net/http/httptest"
// 	"os"
// 	"testing"

// 	"github.com/Microkubes/microservice-security/auth"
// 	"github.com/keitaroinc/goa"

// 	jwt "github.com/dgrijalva/jwt-go"
// 	goaJwt "github.com/keitaroinc/goa/middleware/security/jwt"
// )

// var claims = jwt.MapClaims{
// 	"username":      "test-user",
// 	"userId":        "599316bbf456208abcbcc186",
// 	"roles":         "user",
// 	"organizations": "Org1,Org2",
// 	"scopes":        "api:read api:write",
// }

// var scheme = goa.OAuth2Security{
// 	Flow:             "accessCode",
// 	TokenURL:         "http://resourceServer/oauth2/token",
// 	AuthorizationURL: "http://authorizationServer/oauth2/authorize",
// 	Scopes: map[string]string{
// 		"api:read":  "no description",
// 		"api:write": "no description",
// 	},
// }

// func TestNewOAuth2Security(t *testing.T) {
// 	keysDir, err := ioutil.TempDir("", "keys")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	fmt.Println("Keys will be saved in: ", keysDir)
// 	defer os.RemoveAll(keysDir)

// 	err = generateRSAKeyPairInDir(keysDir, "test_key")

// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	middleware := NewOAuth2Security(keysDir, &scheme)
// 	if middleware == nil {
// 		t.Fatal("Expected OAuth2 middleware to be created!")
// 	}
// }

// func TestNewOAuth2SecurityMiddleware(t *testing.T) {
// 	resolver, key, err := newRSAKeyResolver()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
// 	tokenStr, err := token.SignedString(key)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	req := httptest.NewRequest("GET", "http://example.com", nil)
// 	req.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", tokenStr)}

// 	ctx := context.Background()
// 	modifiedCtx := ctx
// 	middleware := NewOAuth2SecurityMiddleware(resolver, &scheme)
// 	err = middleware(func(c context.Context, w http.ResponseWriter, r *http.Request) error {
// 		// This handler is called AFTER the goa middleware executes.
// 		// It modifies the context, writes the auth object to it
// 		// We want to pass these modified versions back to our chain.
// 		modifiedCtx = c
// 		return nil
// 	})(ctx, nil, req)

// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	hasAuth := auth.HasAuth(modifiedCtx)

// 	if !hasAuth {
// 		t.Fatal("Expected authentication to be set!")
// 	}
// }

// func TestPartitionKeys(t *testing.T) {
// 	resolver, key, err := newRSAKeyResolver()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
// 	tokenStr, err := token.SignedString(key)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	req := httptest.NewRequest("GET", "http://example.com", nil)
// 	req.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", tokenStr)}

// 	rsaKeys, ecdsaKeys, hmacKeys := partitionKeys(resolver.SelectKeys(req))

// 	if !(len(rsaKeys) > 0 || len(ecdsaKeys) > 0 || len(hmacKeys) > 0) {
// 		t.Fatal("Expected to have RSA public key!")
// 	}
// }

// func TestParseClaimScopes(t *testing.T) {
// 	resolver, key, err := newRSAKeyResolver()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
// 	tokenStr, err := token.SignedString(key)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	req := httptest.NewRequest("GET", "http://example.com", nil)
// 	req.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", tokenStr)}

// 	rsaKeys, _, _ := partitionKeys(resolver.SelectKeys(req))

// 	tokenRSA, err := validateRSAKeys(rsaKeys, "RS", tokenStr)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	_, _, err = parseClaimScopes(tokenRSA)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func TestValidateRSAKeys(t *testing.T) {
// 	resolver, key, err := newRSAKeyResolver()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
// 	tokenStr, err := token.SignedString(key)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	req := httptest.NewRequest("GET", "http://example.com", nil)
// 	req.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", tokenStr)}

// 	rsaKeys, _, _ := partitionKeys(resolver.SelectKeys(req))

// 	_, err = validateRSAKeys(rsaKeys, "RS", tokenStr)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func TestValidateECDSAKeys(t *testing.T) {
// 	resolver, key, err := newECDSAKeyResolver()
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
// 	tokenStr, err := token.SignedString(key)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	req := httptest.NewRequest("GET", "http://example.com", nil)
// 	req.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", tokenStr)}

// 	_, ecdsaKeys, _ := partitionKeys(resolver.SelectKeys(req))

// 	_, err = validateECDSAKeys(ecdsaKeys, "ES", tokenStr)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func TestValidateHMACKeys(t *testing.T) {
// 	key := []byte("keys")
// 	resolver := goaJwt.NewSimpleResolver([]goaJwt.Key{key})

// 	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
// 	tokenStr, err := token.SignedString(key)
// 	if err != nil {
// 		t.Fatal(err)
// 	}

// 	req := httptest.NewRequest("GET", "http://example.com", nil)
// 	req.Header["Authorization"] = []string{fmt.Sprintf("Bearer %s", tokenStr)}

// 	_, _, hmacKeys := partitionKeys(resolver.SelectKeys(req))

// 	_, err = validateHMACKeys(hmacKeys, "HS", tokenStr)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func generateRSAKeyPair() (*rsa.PrivateKey, error) {
// 	return rsa.GenerateKey(rand.Reader, 2048)
// }

// func generateECDSAKeyPair() (*ecdsa.PrivateKey, error) {
// 	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
// }

// func newRSAKeyResolver() (goaJwt.KeyResolver, *rsa.PrivateKey, error) {
// 	key, err := generateRSAKeyPair()
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	keys := []goaJwt.Key{}
// 	keys = append(keys, &key.PublicKey)
// 	resolver := goaJwt.NewSimpleResolver(keys)

// 	return resolver, key, nil
// }

// func newECDSAKeyResolver() (goaJwt.KeyResolver, *ecdsa.PrivateKey, error) {
// 	key, err := generateECDSAKeyPair()
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	keys := []goaJwt.Key{}
// 	keys = append(keys, &key.PublicKey)
// 	resolver := goaJwt.NewSimpleResolver(keys)

// 	return resolver, key, nil
// }

// func generateRSAKeyPairInDir(dir string, keyFileName string) error {
// 	keyPair, err := generateRSAKeyPair()
// 	if err != nil {
// 		return err
// 	}

// 	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey) //asn1.Marshal(keyPair.PublicKey)

// 	if err != nil {
// 		return err
// 	}

// 	pubPemKey := &pem.Block{
// 		Type:  "RSA PUBLIC KEY",
// 		Bytes: pubKeyBytes,
// 	}

// 	privPemKey := &pem.Block{
// 		Type:  "RSA PRIVATE KEY",
// 		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
// 	}

// 	pubKeyFile, err := os.Create(fmt.Sprintf("%s/%s.pub", dir, keyFileName))
// 	if err != nil {
// 		return err
// 	}
// 	privKeyFile, err := os.Create(fmt.Sprintf("%s/%s", dir, keyFileName))
// 	if err != nil {
// 		return err
// 	}

// 	err = pem.Encode(pubKeyFile, pubPemKey)
// 	if err != nil {
// 		return err
// 	}
// 	err = pem.Encode(privKeyFile, privPemKey)
// 	if err != nil {
// 		return err
// 	}

// 	return nil
// }
