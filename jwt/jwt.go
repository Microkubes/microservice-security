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
	"github.com/keitaroinc/goa"
	goajwt "github.com/keitaroinc/goa/middleware/security/jwt"
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
			jwtToken := goajwt.ContextJWT(ctx)
			claims := jwtToken.Claims.(jwt.MapClaims)

			if _, ok := claims["userId"]; !ok {
				return jwt.NewValidationError("User ID is missing", jwt.ValidationErrorClaimsInvalid)
			}

			authObj := &auth.Auth{
				UserID: claims["userId"].(string),
			}

			if _, ok := claims["customerID"]; ok {
				authObj.CustomerID = claims["customerID"].(float64)
			}

			if _, ok := claims["username"]; ok {
				authObj.Username = claims["username"].(string)
			}

			if _, ok := claims["fullname"]; ok {
				authObj.Fullname = claims["fullname"].(string)
			}

			if _, ok := claims["email"]; ok {
				authObj.Email = claims["email"].(string)
			}

			if rolesStr, ok := claims["roles"]; ok {
				authObj.Roles = strings.Split(rolesStr.(string), ",")
			}

			if organizations, ok := claims["organizations"]; ok {
				authObj.Organizations = strings.Split(organizations.(string), ",")
			}

			if namespaces, ok := claims["namespaces"]; ok {
				authObj.Namespaces = strings.Split(namespaces.(string), ",")
			}

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
