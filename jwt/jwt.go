package jwt

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"context"

	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/chain"
	"github.com/dgrijalva/jwt-go"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
)

// JWTSecurityType is the name of the JWT security type
const JWTSecurityType = "JWT"

func NewKeyResolver(path string) (goajwt.KeyResolver, error) {
	keys, err := LoadJWTPublicKeys(path)
	if err != nil {
		return nil, err
	}
	return goajwt.NewSimpleResolver(keys), nil
}

func NewJWTSecurityMiddleware(resolver goajwt.KeyResolver, scheme *goa.JWTSecurity) chain.SecurityChainMiddleware {
	goaMiddleware := goajwt.New(resolver, func(handler goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			jwtToken := goajwt.ContextJWT(ctx)
			claims := jwtToken.Claims.(jwt.MapClaims)

			if _, ok := claims["username"]; !ok {
				return jwt.NewValidationError("Username is missing", jwt.ValidationErrorClaimsInvalid)
			}
			if _, ok := claims["userId"]; !ok {
				return jwt.NewValidationError("User ID is missing", jwt.ValidationErrorClaimsInvalid)
			}

			roles := []string{}
			organizations := []string{}
			var username string
			var userID string

			username = claims["username"].(string)
			if _, ok := claims["userId"].(string); !ok {
				return jwt.NewValidationError("Invalid user ID", jwt.ValidationErrorClaimsInvalid)
			}
			userID = claims["userId"].(string)

			if rolesStr, ok := claims["roles"]; ok {
				roles = strings.Split(rolesStr.(string), ",")
			}
			if organizationsStr, ok := claims["organizations"]; ok {
				organizations = strings.Split(organizationsStr.(string), ",")
			}

			authObj := &auth.Auth{
				Roles:         roles,
				Organizations: organizations,
				Username:      username,
				UserID:        userID,
			}

			return handler(auth.SetAuth(ctx, authObj), rw, req)
		}
	}, scheme)
	return chain.ToSecurityChainMiddleware(JWTSecurityType, goaMiddleware)
}

func NewJWTSecurity(keysDir string, scheme *goa.JWTSecurity) chain.SecurityChainMiddleware {
	resolver, err := NewKeyResolver(keysDir)
	if err != nil {
		panic(err)
	}
	return NewJWTSecurityMiddleware(resolver, scheme)
}

// LoadJWTPublicKeys loads PEM encoded RSA public keys used to validate and decrypt the JWT.
func LoadJWTPublicKeys(path string) ([]goajwt.Key, error) {
	keyFiles, err := filepath.Glob(fmt.Sprintf("%s/*.pub", path))
	if err != nil {
		return nil, err
	}
	keys := make([]goajwt.Key, len(keyFiles))
	for i, keyFile := range keyFiles {
		pem, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		key, err := jwtgo.ParseRSAPublicKeyFromPEM([]byte(pem))
		if err != nil {
			return nil, fmt.Errorf("failed to load key %s: %s", keyFile, err)
		}
		keys[i] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("couldn't load public keys for JWT security")
	}

	return keys, nil
}
