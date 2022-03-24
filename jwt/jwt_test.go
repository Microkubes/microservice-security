package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Microkubes/microservice-security/chain"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	"github.com/stretchr/testify/assert"
)

func generateRSAKeyPair() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
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

func getTest(c echo.Context) error {
	return c.JSON(200, "token valid")
}
func TestJWTMiddleware(t *testing.T) {
	claims := jwt.MapClaims{}
	claims["userId"] = "test"
	e := echo.New()
	e.GET("/", getTest)
	keysDir, err := ioutil.TempDir("", "keys")
	assert.NoError(t, err, "error creating temp keys dir")
	defer os.RemoveAll(keysDir)

	err = generateRSAKeyPairInDir(keysDir, "test_key")
	assert.NoError(t, err, "error genererating key pair")

	privKey, err := ioutil.ReadFile(fmt.Sprintf("%s/test_key", keysDir))
	assert.NoError(t, err, "error reading private key")

	ch := chain.Chain{}
	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(privKey)
	assert.NoError(t, err, "error parsing signing key")

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(signKey)
	assert.NoError(t, err, "error signing jwt token")

	pks, err := LoadJWTPublicKeys(keysDir)
	assert.NoError(t, err, "error loading public keys")
	jwt, err := NewJWTMiddleware(pks["test_key"])
	assert.NoError(t, err, "error creating jwt middleware")

	ch.MiddlewareFuncs = append(ch.MiddlewareFuncs, jwt)
	ch.Execute(e)
	req, err := http.NewRequest(http.MethodGet, "/", nil)
	assert.NoError(t, err, "error creating request")

	req.Header.Set("authorization", "bearer "+token)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	req.Header.Set("authorization", "bearer "+token+"invalid")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code, "error verifying invalid token")
}
