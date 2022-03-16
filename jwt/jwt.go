package jwt

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strings"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-security/chain"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
	em "github.com/labstack/echo/v4/middleware"
)

// JWTSecurityType is the name of the JWT security type
const JWTSecurityType = "JWT"

// NewKeyResolver creates a simple key resolver for the JWT middleware. It loads
// the public keys from a specified directory (path). The public key files
// MUST end in *.pub .
// func NewKeyResolver(path string) (goajwt.KeyResolver, error) {
// 	keys, err := LoadJWTPublicKeys(path)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return goajwt.NewSimpleResolver(keys), nil
// }

// NewJWTSecurityMiddleware creates a new chain.SecurityChainMiddleware with a given KeyResolver and
// JWTSecurity configuration.
// As resolver you may pass the simple key resolver created with NewKeyResolver or you may pass a more
// sophisticated key-resolver.
// The scheme is obtained from the generated Goadesign JWT security.
// func NewJWTSecurityMiddleware(resolver goajwt.KeyResolver, scheme *goa.JWTSecurity) chain.SecurityChainMiddleware {
// 	goaMiddleware := goajwt.New(resolver, func(handler goa.Handler) goa.Handler {
// 		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
// 			jwtToken := goajwt.ContextJWT(ctx)
// 			claims := jwtToken.Claims.(jwt.MapClaims)

// 			if _, ok := claims["userId"]; !ok {
// 				return jwt.NewValidationError("User ID is missing", jwt.ValidationErrorClaimsInvalid)
// 			}

// 			authObj := &auth.Auth{
// 				UserID: claims["userId"].(string),
// 			}

// 			if _, ok := claims["customerID"]; ok {
// 				authObj.CustomerID = claims["customerID"].(float64)
// 			}

// 			if _, ok := claims["username"]; ok {
// 				authObj.Username = claims["username"].(string)
// 			}

// 			if _, ok := claims["fullname"]; ok {
// 				authObj.Fullname = claims["fullname"].(string)
// 			}

// 			if _, ok := claims["email"]; ok {
// 				authObj.Email = claims["email"].(string)
// 			}

// 			if rolesStr, ok := claims["roles"]; ok {
// 				authObj.Roles = strings.Split(rolesStr.(string), ",")
// 			}

// 			if organizations, ok := claims["organizations"]; ok {
// 				authObj.Organizations = strings.Split(organizations.(string), ",")
// 			}

// 			if namespaces, ok := claims["namespaces"]; ok {
// 				authObj.Namespaces = strings.Split(namespaces.(string), ",")
// 			}

// 			return handler(auth.SetAuth(ctx, authObj), rw, req)
// 		}
// 	}, scheme)
// 	return chain.ToSecurityChainMiddleware(JWTSecurityType, goaMiddleware)
// }

// NewJWTMiddleware
func NewJWTMiddleware(rsaKey *rsa.PublicKey) (chain.EchoMiddleware, error) {
	// pubKey, err := ioutil.ReadFile(fp)
	// if err != nil {
	// 	return nil, err
	// }
	// rsaKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKey)
	// if err != nil {
	// 	return nil, err
	// }
	// After validating the token set Auth object in claims
	return chain.EchoMiddleware(em.JWTWithConfig(em.JWTConfig{
		ContextKey:    "user",
		SigningKey:    rsaKey,
		SigningMethod: "RS256",
		TokenLookup:   "header:authorization",
		SuccessHandler: func(c echo.Context) {
			token := c.Get("user").(*jwt.Token)
			claims := token.Claims.(jwt.MapClaims)
			if _, ok := claims["userId"]; !ok {
				c.JSON(400, "user id is missing from the claims")
				return
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
			c.Set("userInfo", authObj)
		},
	})), nil
}

// NewJWTSecurity creates a JWT SecurityChainMiddleware using a simple key resolver
// that loads the public keys from the keysDir. The key files must end in *.pub.
// The scheme is obtained from the generated Goadesign JWT security.
// func NewJWTSecurity(keysDir string, scheme *goa.JWTSecurity) chain.SecurityChainMiddleware {
// 	resolver, err := NewKeyResolver(keysDir)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return NewJWTSecurityMiddleware(resolver, scheme)
// }

// LoadJWTPublicKeys loads PEM encoded RSA public keys used to validate and decrypt the JWT.
func LoadJWTPublicKeys(path string) (map[string]*rsa.PublicKey, error) {
	keyFiles, err := filepath.Glob(fmt.Sprintf("%s/*.pub", path))
	if err != nil {
		return nil, err
	}
	keys := make(map[string]*rsa.PublicKey, 0)
	for _, keyFile := range keyFiles {
		pem, err := ioutil.ReadFile(keyFile)
		if err != nil {
			return nil, err
		}
		key, err := jwtgo.ParseRSAPublicKeyFromPEM([]byte(pem))
		if err != nil {
			return nil, fmt.Errorf("failed to load key %s: %s", keyFile, err)
		}
		keys[keyFile] = key
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("couldn't load public keys for JWT security")
	}
	fmt.Println("the keys before return ", keys)
	return keys, nil
}
