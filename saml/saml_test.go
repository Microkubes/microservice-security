package saml

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gopkg.in/h2non/gock.v1"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-tools/config"
	"github.com/crewjam/saml/samlsp"
	"github.com/dgrijalva/jwt-go"
)

var key = func() crypto.PrivateKey {
	b, _ := pem.Decode([]byte(`-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0OhbMuizgtbFOfwbK7aURuXhZx6VRuAs3nNibiuifwCGz6u9
yy7bOR0P+zqN0YkjxaokqFgra7rXKCdeABmoLqCC0U+cGmLNwPOOA0PaD5q5xKhQ
4Me3rt/R9C4Ca6k3/OnkxnKwnogcsmdgs2l8liT3qVHP04Oc7Uymq2v09bGb6nPu
fOrkXS9F6mSClxHG/q59AGOWsXK1xzIRV1eu8W2SNdyeFVU1JHiQe444xLoPul5t
InWasKayFsPlJfWNc8EoU8COjNhfo/GovFTHVjh9oUR/gwEFVwifIHihRE0Hazn2
EQSLaOr2LM0TsRsQroFjmwSGgI+X2bfbMTqWOQIDAQABAoIBAFWZwDTeESBdrLcT
zHZe++cJLxE4AObn2LrWANEv5AeySYsyzjRBYObIN9IzrgTb8uJ900N/zVr5VkxH
xUa5PKbOcowd2NMfBTw5EEnaNbILLm+coHdanrNzVu59I9TFpAFoPavrNt/e2hNo
NMGPSdOkFi81LLl4xoadz/WR6O/7N2famM+0u7C2uBe+TrVwHyuqboYoidJDhO8M
w4WlY9QgAUhkPyzZqrl+VfF1aDTGVf4LJgaVevfFCas8Ws6DQX5q4QdIoV6/0vXi
B1M+aTnWjHuiIzjBMWhcYW2+I5zfwNWRXaxdlrYXRukGSdnyO+DH/FhHePJgmlkj
NInADDkCgYEA6MEQFOFSCc/ELXYWgStsrtIlJUcsLdLBsy1ocyQa2lkVUw58TouW
RciE6TjW9rp31pfQUnO2l6zOUC6LT9Jvlb9PSsyW+rvjtKB5PjJI6W0hjX41wEO6
fshFELMJd9W+Ezao2AsP2hZJ8McCF8no9e00+G4xTAyxHsNI2AFTCQcCgYEA5cWZ
JwNb4t7YeEajPt9xuYNUOQpjvQn1aGOV7KcwTx5ELP/Hzi723BxHs7GSdrLkkDmi
Gpb+mfL4wxCt0fK0i8GFQsRn5eusyq9hLqP/bmjpHoXe/1uajFbE1fZQR+2LX05N
3ATlKaH2hdfCJedFa4wf43+cl6Yhp6ZA0Yet1r8CgYEAwiu1j8W9G+RRA5/8/DtO
yrUTOfsbFws4fpLGDTA0mq0whf6Soy/96C90+d9qLaC3srUpnG9eB0CpSOjbXXbv
kdxseLkexwOR3bD2FHX8r4dUM2bzznZyEaxfOaQypN8SV5ME3l60Fbr8ajqLO288
wlTmGM5Mn+YCqOg/T7wjGmcCgYBpzNfdl/VafOROVbBbhgXWtzsz3K3aYNiIjbp+
MunStIwN8GUvcn6nEbqOaoiXcX4/TtpuxfJMLw4OvAJdtxUdeSmEee2heCijV6g3
ErrOOy6EqH3rNWHvlxChuP50cFQJuYOueO6QggyCyruSOnDDuc0BM0SGq6+5g5s7
H++S/wKBgQDIkqBtFr9UEf8d6JpkxS0RXDlhSMjkXmkQeKGFzdoJcYVFIwq8jTNB
nJrVIGs3GcBkqGic+i7rTO1YPkquv4dUuiIn+vKZVoO6b54f+oPBXd4S0BnuEqFE
rdKNuCZhiaE2XD9L/O9KP1fh5bfEcKwazQ23EvpJHBMm8BGC+/YZNw==
-----END RSA PRIVATE KEY-----`))
	k, _ := x509.ParsePKCS1PrivateKey(b.Bytes)
	return k
}()

var cert = func() *x509.Certificate {
	b, _ := pem.Decode([]byte(`-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIJAPr/Mrlc8EGhMA0GCSqGSIb3DQEBBQUAMBoxGDAWBgNV
BAMMD3d3dy5leGFtcGxlLmNvbTAeFw0xNTEyMjgxOTE5NDVaFw0yNTEyMjUxOTE5
NDVaMBoxGDAWBgNVBAMMD3d3dy5leGFtcGxlLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBANDoWzLos4LWxTn8Gyu2lEbl4WcelUbgLN5zYm4ron8A
hs+rvcsu2zkdD/s6jdGJI8WqJKhYK2u61ygnXgAZqC6ggtFPnBpizcDzjgND2g+a
ucSoUODHt67f0fQuAmupN/zp5MZysJ6IHLJnYLNpfJYk96lRz9ODnO1Mpqtr9PWx
m+pz7nzq5F0vRepkgpcRxv6ufQBjlrFytccyEVdXrvFtkjXcnhVVNSR4kHuOOMS6
D7pebSJ1mrCmshbD5SX1jXPBKFPAjozYX6PxqLxUx1Y4faFEf4MBBVcInyB4oURN
B2s59hEEi2jq9izNE7EbEK6BY5sEhoCPl9m32zE6ljkCAwEAAaNQME4wHQYDVR0O
BBYEFB9ZklC1Ork2zl56zg08ei7ss/+iMB8GA1UdIwQYMBaAFB9ZklC1Ork2zl56
zg08ei7ss/+iMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADggEBAAVoTSQ5
pAirw8OR9FZ1bRSuTDhY9uxzl/OL7lUmsv2cMNeCB3BRZqm3mFt+cwN8GsH6f3uv
NONIhgFpTGN5LEcXQz89zJEzB+qaHqmbFpHQl/sx2B8ezNgT/882H2IH00dXESEf
y/+1gHg2pxjGnhRBN6el/gSaDiySIMKbilDrffuvxiCfbpPN0NRRiPJhd2ay9KuL
/RxQRl1gl9cHaWiouWWba1bSBb2ZPhv2rPMUsFo98ntkGCObDX6Y1SpkqmoTbrsb
GFsTG2DLxnvr4GdN1BSr0Uu/KV3adj47WkXVPeMYQti/bQmxQB8tRFhrw80qakTL
UzreO96WzlBBMtY=
-----END CERTIFICATE-----`))
	c, _ := x509.ParseCertificate(b.Bytes)
	return c
}()

var rootURL, _ = url.Parse("http://localhost:8082")
var idpMetadataURL, _ = url.Parse("https://www.testshib.org/metadata/testshib-providers.xml")
var samlSP, _ = samlsp.New(samlsp.Options{
	IDPMetadataURL: idpMetadataURL,
	URL:            *rootURL,
	Key:            key.(*rsa.PrivateKey),
	Certificate:    cert,
})

var samlConfig = &config.SAMLConfig{
	IdentityProviderURL:    "http://127.0.0.1:8081/saml/idp",
	RegistrationServiceURL: "http://127.0.0.1:8081/users",
	UserServiceURL:         "http://127.0.0.1:8081/users",
}

func TestNewSAMLSecurity(t *testing.T) {
	middleware := NewSAMLSecurity(samlSP, samlConfig)
	if middleware == nil {
		t.Fatal("Expected SAML middleware to be created!")
	}
}

func TestNewSAMLSecurityMiddleware(t *testing.T) {
	secret := x509.MarshalPKCS1PrivateKey(samlSP.ServiceProvider.Key)
	claims := TokenClaims{}
	claims.Audience = "http://localhost:8082/saml/metadata"
	claims.Attributes = map[string][]string{
		"uid": []string{"59a006ae0000000000000000"},
		"eduPersonPrincipalName": []string{"test@example.org"},
		"eduPersonAffiliation":   []string{"user, admin"},
		"organizations":          []string{"Ozrg1, Org2"},
	}
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := tokenHS.SignedString(secret)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{
		Name:       "token",
		Value:      tokenStr,
		Path:       "/",
		Domain:     "www.example.com",
		Expires:    expire,
		RawExpires: expire.Format(time.UnixDate),
		MaxAge:     86400,
		Secure:     true,
		HttpOnly:   true,
		Raw:        "test=tcookie",
		Unparsed:   []string{"test=tcookie"},
	}
	req.AddCookie(&cookie)

	ctx := context.Background()
	modifiedCtx := ctx
	middleware := NewSAMLSecurityMiddleware(samlSP, samlConfig)
	err := middleware(func(c context.Context, w http.ResponseWriter, r *http.Request) error {
		// This handler is called AFTER the goa middleware executes.
		// It modifies the context, writes the auth object to it
		// We want to pass these modified versions back to our chain.
		modifiedCtx = c
		return nil
	})(ctx, rw, req)

	if err != nil {
		t.Fatal(err)
	}

	hasAuth := auth.HasAuth(modifiedCtx)

	if !hasAuth {
		t.Fatal("Expected authentication to be set!")
	}
}

func TestNewSAMLSecurityMiddlewareExpiredToken(t *testing.T) {
	secret := x509.MarshalPKCS1PrivateKey(samlSP.ServiceProvider.Key)
	claims := TokenClaims{}
	claims.Audience = "http://localhost:8082/saml/metadata"
	claims.Attributes = map[string][]string{
		"uid":                  []string{"59a006ae0000000000000000"},
		"givenName":            []string{"test-user"},
		"eduPersonAffiliation": []string{"user, admin"},
		"organizations":        []string{"Ozrg1, Org2"},
	}
	claims.StandardClaims.ExpiresAt = 1507543075
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := tokenHS.SignedString(secret)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{
		Name:       "token",
		Value:      tokenStr,
		Path:       "/",
		Domain:     "www.example.com",
		Expires:    expire,
		RawExpires: expire.Format(time.UnixDate),
		MaxAge:     86400,
		Secure:     true,
		HttpOnly:   true,
		Raw:        "test=tcookie",
		Unparsed:   []string{"test=tcookie"},
	}
	req.AddCookie(&cookie)

	ctx := context.Background()
	modifiedCtx := ctx
	middleware := NewSAMLSecurityMiddleware(samlSP, samlConfig)
	err := middleware(func(c context.Context, w http.ResponseWriter, r *http.Request) error {
		// This handler is called AFTER the goa middleware executes.
		// It modifies the context, writes the auth object to it
		// We want to pass these modified versions back to our chain.
		modifiedCtx = c
		return nil
	})(ctx, rw, req)

	if err == nil {
		t.Fatal("Nil error for expired SAML token")
	}
}

func TestNewSAMLSecurityMiddlewareInvalidAudience(t *testing.T) {
	secret := x509.MarshalPKCS1PrivateKey(samlSP.ServiceProvider.Key)
	claims := TokenClaims{}
	claims.Audience = "http://test.com/saml/metadata"
	claims.Attributes = map[string][]string{
		"uid":                  []string{"59a006ae0000000000000000"},
		"givenName":            []string{"test-user"},
		"eduPersonAffiliation": []string{"user, admin"},
		"organizations":        []string{"Ozrg1, Org2"},
	}
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := tokenHS.SignedString(secret)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{
		Name:       "token",
		Value:      tokenStr,
		Path:       "/",
		Domain:     "www.example.com",
		Expires:    expire,
		RawExpires: expire.Format(time.UnixDate),
		MaxAge:     86400,
		Secure:     true,
		HttpOnly:   true,
		Raw:        "test=tcookie",
		Unparsed:   []string{"test=tcookie"},
	}
	req.AddCookie(&cookie)

	ctx := context.Background()
	modifiedCtx := ctx
	middleware := NewSAMLSecurityMiddleware(samlSP, samlConfig)
	err := middleware(func(c context.Context, w http.ResponseWriter, r *http.Request) error {
		// This handler is called AFTER the goa middleware executes.
		// It modifies the context, writes the auth object to it
		// We want to pass these modified versions back to our chain.
		modifiedCtx = c
		return nil
	})(ctx, rw, req)

	if err == nil {
		t.Fatal("Nil error, expected: 'invalid audience from SAML token, got http://test.com/saml/metadata, expected http://localhost:8082/saml/metadata'")
	}
}

func TestNewSAMLSecurityMiddlewareEmptyToken(t *testing.T) {
	rw := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "http://example.com", nil)
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{
		Name:       "token",
		Value:      "",
		Path:       "/",
		Domain:     "www.example.com",
		Expires:    expire,
		RawExpires: expire.Format(time.UnixDate),
		MaxAge:     86400,
		Secure:     true,
		HttpOnly:   true,
		Raw:        "test=tcookie",
		Unparsed:   []string{"test=tcookie"},
	}
	req.AddCookie(&cookie)

	ctx := context.Background()
	modifiedCtx := ctx
	middleware := NewSAMLSecurityMiddleware(samlSP, samlConfig)
	err := middleware(func(c context.Context, w http.ResponseWriter, r *http.Request) error {
		// This handler is called AFTER the goa middleware executes.
		// It modifies the context, writes the auth object to it
		// We want to pass these modified versions back to our chain.
		modifiedCtx = c
		return nil
	})(ctx, rw, req)

	if err == nil {
		t.Fatal("Nil error, expected: 'invalid SAML token: token contains an invalid number of segments'")
	}
}

func TestRedirectUser(t *testing.T) {
	req := httptest.NewRequest("GET", "http://example.com/foo", nil)
	rw := httptest.NewRecorder()

	RedirectUser(samlSP, rw, req)

	if rw.Header().Get("Location") == "" && rw.Header().Get("Content-type") == "" {
		t.Fatal("Expected Location or Content-type to be set in the header")
	}

	cookieName := rw.Result().Cookies()[0].Name
	if !strings.HasPrefix(cookieName, "saml_") {
		t.Fatal("Expected SAML request cookie to be set")
	}
}

func TestGetPossibleRequestIDs(t *testing.T) {
	secret := x509.MarshalPKCS1PrivateKey(samlSP.ServiceProvider.Key)
	claims := jwt.MapClaims{}
	claims["id"] = "dsadsa5767dsa45qwq"
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, _ := tokenHS.SignedString(secret)

	req := httptest.NewRequest("GET", "http://example.com", nil)
	expire := time.Now().AddDate(0, 0, 1)
	cookie := http.Cookie{
		Name:       "saml_response_token",
		Value:      tokenStr,
		Path:       "/",
		Domain:     "www.example.com",
		Expires:    expire,
		RawExpires: expire.Format(time.UnixDate),
		MaxAge:     86400,
		Secure:     true,
		HttpOnly:   true,
		Raw:        "test=tcookie",
		Unparsed:   []string{"test=tcookie"},
	}
	req.AddCookie(&cookie)

	ids := getPossibleRequestIDs(samlSP, req)

	if len(ids) < 1 {
		t.Fatal("Expected IDs on the request")
	}

	if ids[0] != "dsadsa5767dsa45qwq" {
		t.Errorf("Expected id is  %s, got %s", "dsadsa5767dsa45qwq", ids[0])
	}

}

func TestRandomBytes(t *testing.T) {
	bytes := randomBytes(40)
	if len(bytes) != 40 {
		t.Fatal("Expected byte array of 40 elements")
	}
}

func TestRegisterUser(t *testing.T) {
	gock.New("http://127.0.0.1:8081").
		Post("/users/register").
		Reply(201).
		JSON(map[string]interface{}{
			"id":         "59804b3c0000000000000000",
			"fullname":   "Jon Smith",
			"username":   "jons",
			"email":      "jon@test.com",
			"externalId": "qwe04b3c000000qwertydgfsd",
			"roles":      []string{"admin", "user"},
			"active":     false,
		})

	user, err := registerUser("jon@test.com", "Jon", "Smith", samlSP, samlConfig.RegistrationServiceURL)

	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("Nil user")
	}
}

func TestFindUser(t *testing.T) {
	gock.New("http://127.0.0.1:8081").
		Post("/users/find/email").
		Reply(200).
		JSON(map[string]interface{}{
			"id":         "59804b3c0000000000000000",
			"fullname":   "Jon Smith",
			"username":   "jons",
			"email":      "jon@test.com",
			"externalId": "qwe04b3c000000qwertydgfsd",
			"roles":      []string{"admin", "user"},
			"active":     false,
		})

	user, err := findUser("jon@test.com", samlSP, samlConfig.UserServiceURL)

	if err != nil {
		t.Fatal(err)
	}
	if user == nil {
		t.Fatal("Nil user")
	}
}

func TestRegisterSP(t *testing.T) {
	gock.New("http://127.0.0.1:8081").
		Post("/saml/idp/services").
		Reply(201)

	_, err := RegisterSP(samlSP, samlConfig)
	if err != nil {
		t.Fatal(err)
	}
}

func TestUnregisterSP(t *testing.T) {
	gock.New("http://127.0.0.1:8081").
		Delete("/saml/idp/services").
		Reply(200)

	UnregisterSP(samlSP, samlConfig)
}

func TestMakeRequest(t *testing.T) {
	payload := []byte(`{
	    "data": "something"
	  }`)
	client := &http.Client{}

	gock.New("http://test.com").
		Post("/users").
		Reply(201)

	gock.New("http://test.com").
		Delete("/users").
		Reply(201)

	resp, err := makeRequest(client, http.MethodPost, payload, "http://test.com/users", samlSP)
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil {
		t.Fatal("Nil response")
	}
}

func TestGenerateSAMLToken(t *testing.T) {
	token, err := generateSAMLToken(samlSP)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("empty token string")
	}
}
