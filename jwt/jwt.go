package jwt

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"path/filepath"
	"strings"

	"context"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-security/chain"
	"github.com/dgrijalva/jwt-go"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
	goajwt "github.com/goadesign/goa/middleware/security/jwt"
)

// JWTSecurityType is the name of the JWT security type
const JWTSecurityType = "JWT"

// NewKeyResolver creates a simple key resolver for the JWT middleware. It loads
// the public keys from a specified directory (path). The public key files
// MUST end in *.pub .
func NewKeyResolver(path string) (goajwt.KeyResolver, error) {
	keys, err := LoadJWTPublicKeys(path)
	if err != nil {
		return nil, err
	}
	return goajwt.NewSimpleResolver(keys), nil
}

// NewJWTSecurityMiddleware creates a new chain.SecurityChainMiddleware with a given KeyResolver and
// JWTSecurity configuration.
// As resolver you may pass the simple key resolver created with NewKeyResolver or you may pass a more
// sophisticated key-resolver.
// The scheme is obtained from the generated Goadesign JWT security.
func NewJWTSecurityMiddleware(resolver goajwt.KeyResolver, scheme *goa.JWTSecurity) chain.SecurityChainMiddleware {
	goaMiddleware := goajwt.New(resolver, func(handler goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			fmt.Println("JWT post processing")
			jwtToken := goajwt.ContextJWT(ctx)
			claims := jwtToken.Claims.(jwt.MapClaims)

			if _, ok := claims["username"]; !ok {
				fmt.Println("Username missing")
				return jwt.NewValidationError("Username is missing", jwt.ValidationErrorClaimsInvalid)
			}
			if _, ok := claims["userId"]; !ok {
				fmt.Println("Password missing")
				return jwt.NewValidationError("User ID is missing", jwt.ValidationErrorClaimsInvalid)
			}
			fmt.Println("Username and userID OK")
			roles := []string{}
			organizations := []string{}
			namespaces := []string{}
			var username string
			var userID string

			username = claims["username"].(string)
			if _, ok := claims["userId"].(string); !ok {
				fmt.Printf("User ID is not string? Then what is it? -> %v\n", claims["userId"])
				return jwt.NewValidationError("Invalid user ID", jwt.ValidationErrorClaimsInvalid)
			}
			userID = claims["userId"].(string)

			if rolesStr, ok := claims["roles"]; ok {
				roles = strings.Split(rolesStr.(string), ",")
			}
			if organizationsStr, ok := claims["organizations"]; ok {
				organizations = strings.Split(organizationsStr.(string), ",")
			}
			if namespacesStr, ok := claims["namespaces"]; ok {
				namespaces = strings.Split(namespacesStr.(string), ",")
			}

			authObj := &auth.Auth{
				Roles:         roles,
				Organizations: organizations,
				Username:      username,
				UserID:        userID,
				Namespaces:    namespaces,
			}
			fmt.Printf("Auth created: %v\n", authObj)
			return handler(auth.SetAuth(ctx, authObj), rw, req)
		}
	}, scheme)
	return chain.ToSecurityChainMiddleware(JWTSecurityType, goaMiddleware)
}

// NewJWTSecurity creates a JWT SecurityChainMiddleware using a simple key resolver
// that loads the public keys from the keysDir. The key files must end in *.pub.
// The scheme is obtained from the generated Goadesign JWT security.
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
