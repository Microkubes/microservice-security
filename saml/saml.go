package saml

import (
	"fmt"
	"net/http"
	"context"
	"strings"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"github.com/dgrijalva/jwt-go"

	"github.com/goadesign/goa"
	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/chain"
)

const (
	// SAMLSecurityType is the name of the security type (JWT, OAUTH2, SAML...)
	SAMLSecurityType = "SAML"
	// Cookie name for saml token
	CookieName = "saml_token"
)

// SAML claims
type TokenClaims struct {
	jwt.StandardClaims
	Attributes map[string]interface{} `json:"attr"`
}

// NewSAMLSecurity creates a SAML SecurityChainMiddleware using RSA private key.
func NewSAMLSecurity(cert string, key string) chain.SecurityChainMiddleware {
	rsaPrivateKey, err := loadRSAPrivateKey(cert, key)
	if err != nil {
		panic(err)
	}
	goaMiddleware := NewSAMLSecurityMiddleware(rsaPrivateKey)
	return chain.ToSecurityChainMiddleware(SAMLSecurityType, goaMiddleware)
}

// NewSAMLSecurityMiddleware creates a middleware that checks for the presence of a cookie in the header
// and validates its content.
// The steps taken by the middleware are:
// 1. Validate the cookie "saml_token" present in the header against the key
func NewSAMLSecurityMiddleware(rsaPrivateKey *rsa.PrivateKey) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			cookie, err := req.Cookie(CookieName)
			if err != nil {
				return goa.ErrUnauthorized(fmt.Sprintf("missing cookie %s", CookieName))
			}

			// fmt.Println(cookie.Value)
			// sB := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)

			// claims := TokenClaims{}
			// claims.Attributes = map[string]interface{}{
			// 	"userId": "59a006ae0000000000000000",
			// 	"username": "test-user",
			// 	"roles": "user, admin",
			// 	"organizations": "Ozrg1, Org2",
			// }
			// tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			// tokenStr, err := tokenHS.SignedString(sB)

			// fmt.Println("TOKEN")
			// fmt.Println(tokenStr)

			tokenClaims := TokenClaims{}
			token, err := jwt.ParseWithClaims(cookie.Value, &tokenClaims, func(t *jwt.Token) (interface{}, error) {
				secretBlock := x509.MarshalPKCS1PrivateKey(rsaPrivateKey)
				return secretBlock, nil
			})

			if err != nil || !token.Valid {
				fmt.Println(err)
				return goa.ErrUnauthorized(fmt.Sprintf("invalid SAML token: %s", err))
			}

			if err := tokenClaims.StandardClaims.Valid(); err != nil {
				return goa.ErrUnauthorized("invalid SAML token standard claims: %s", err)
			}

			if tokenClaims.Audience != m.ServiceProvider.Metadata().EntityID {
				return goa.ErrUnauthorized("invalid audience from SAML token")
			}

			attributes := tokenClaims.Attributes

			if _, ok := attributes["username"]; !ok {
				return jwt.NewValidationError("Username is missing form SAML token", jwt.ValidationErrorClaimsInvalid)
			}
			if _, ok := attributes["userId"]; !ok {
				return jwt.NewValidationError("User ID is missing form SAML token", jwt.ValidationErrorClaimsInvalid)
			}

			var username string
			var userID string
			roles := []string{}
			organizations := []string{}

			if _, ok := attributes["username"].(string); !ok {
				return jwt.NewValidationError("invalid username from SAML token", jwt.ValidationErrorClaimsInvalid)
			}
			username = attributes["username"].(string)
			if _, ok := attributes["userId"].(string); !ok {
				return jwt.NewValidationError("invalid user ID from SAML token", jwt.ValidationErrorClaimsInvalid)
			}
			userID = attributes["userId"].(string)

			if rolesStr, ok := attributes["roles"]; ok {
				roles = strings.Split(rolesStr.(string), ",")
			}
			if organizationsStr, ok := attributes["organizations"]; ok {
				organizations = strings.Split(organizationsStr.(string), ",")
			}

			authObj := &auth.Auth{
				Roles:         roles,
				Organizations: organizations,
				Username:      username,
				UserID:        userID,
			}

			return h(auth.SetAuth(ctx, authObj), rw, req)
		}
	}
}

// Load RSA private key
func loadRSAPrivateKey(cert string, key string) (*rsa.PrivateKey, error) {
	keyPair, err := tls.LoadX509KeyPair(cert, key)
	 if err != nil {
        return nil, err
    }

    return keyPair.PrivateKey.(*rsa.PrivateKey), nil
} 	