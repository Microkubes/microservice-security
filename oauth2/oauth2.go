package oauth2

import (
	"context"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-security/chain"
	jormungandrJwt "github.com/Microkubes/microservice-security/jwt"
	jwt "github.com/dgrijalva/jwt-go"
	"github.com/keitaroinc/goa"
	goaJwt "github.com/keitaroinc/goa/middleware/security/jwt"

	"crypto/ecdsa"
	"crypto/rsa"
)

// OAuth2SecurityType is the name of the security type (JWT, OAUTH2, SAML...)
const OAuth2SecurityType = "OAuth2"

// NewOAuth2Security creates a OAuth2 SecurityChainMiddleware using a simple key resolver
// that loads the public keys from the keysDir. The key files must end in *.pub.
// The scheme is obtained from app/security.go.
func NewOAuth2Security(keysDir string, scheme *goa.OAuth2Security) chain.SecurityChainMiddleware {
	resolver, err := jormungandrJwt.NewKeyResolver(keysDir)
	if err != nil {
		panic(err)
	}
	goaMiddleware := NewOAuth2SecurityMiddleware(resolver, scheme)
	return chain.ToSecurityChainMiddleware(OAuth2SecurityType, goaMiddleware)
}

// NewOAuth2SecurityMiddleware creates a middleware that checks for the presence of an authorization header
// and validates its content.
// The steps taken by the middleware are:
// 1. Validate the "Bearer" token present in the "Authorization" header against the key(s)
// 2. If scopes are defined for the action validate them against the "scopes" JWT claim
func NewOAuth2SecurityMiddleware(resolver goaJwt.KeyResolver, scheme *goa.OAuth2Security) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			authorization := req.Header["Authorization"]
			if authorization == nil {
				return goa.ErrUnauthorized("missing auth header")
			}
			tokenHeader := authorization[0]
			if len(tokenHeader) < 9 || !strings.HasPrefix(tokenHeader, "Bearer ") {
				return goa.ErrUnauthorized("invalid auth header")
			}
			tokenHeader = tokenHeader[7:]

			rsaKeys, ecdsaKeys, hmacKeys := partitionKeys(resolver.SelectKeys(req))

			var (
				token     *jwt.Token
				err       error
				validated = false
			)

			if len(rsaKeys) > 0 {
				token, err = validateRSAKeys(rsaKeys, "RS", tokenHeader)
				if err == nil {
					validated = true
				}
			}

			if !validated && len(ecdsaKeys) > 0 {
				token, err = validateECDSAKeys(ecdsaKeys, "ES", tokenHeader)
				if err == nil {
					validated = true
				}
			}

			if !validated && len(hmacKeys) > 0 {
				token, err = validateHMACKeys(hmacKeys, "HS", tokenHeader)
				if err == nil {
					validated = true
				}
			}

			if !validated {
				return goaJwt.ErrJWTError("JWT validation failed")
			}

			scopesInClaim, scopesInClaimList, err := parseClaimScopes(token)
			if err != nil {
				return goaJwt.ErrJWTError(err)
			}

			requiredScopes := reflect.ValueOf(scheme.Scopes).MapKeys()

			for _, scope := range requiredScopes {
				if !scopesInClaim[scope.String()] {
					msg := "authorization failed: required 'scopes' not present in JWT claim for OAuth2"
					return goaJwt.ErrJWTError(msg, "required", requiredScopes, "scopes", scopesInClaimList)
				}
			}

			claims := token.Claims.(jwt.MapClaims)

			if _, ok := claims["username"]; !ok {
				return jwt.NewValidationError("Username is missing", jwt.ValidationErrorClaimsInvalid)
			}
			if _, ok := claims["userId"]; !ok {
				return jwt.NewValidationError("User ID is missing", jwt.ValidationErrorClaimsInvalid)
			}

			roles := []string{}
			organizations := []string{}
			namespaces := []string{}
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

			return h(auth.SetAuth(ctx, authObj), rw, req)
		}
	}
}

// partitionKeys sorts keys by their type.
func partitionKeys(keys []goaJwt.Key) ([]*rsa.PublicKey, []*ecdsa.PublicKey, [][]byte) {
	var (
		rsaKeys   []*rsa.PublicKey
		ecdsaKeys []*ecdsa.PublicKey
		hmacKeys  [][]byte
	)

	for _, key := range keys {
		switch k := key.(type) {
		case *rsa.PublicKey:
			rsaKeys = append(rsaKeys, k)
		case *ecdsa.PublicKey:
			ecdsaKeys = append(ecdsaKeys, k)
		case []byte:
			hmacKeys = append(hmacKeys, k)
		case string:
			hmacKeys = append(hmacKeys, []byte(k))
		}
	}

	return rsaKeys, ecdsaKeys, hmacKeys
}

// parseClaimScopes parses the "scopes" parameter in the Claims. It supports two formats:
//
// * a list of string
//
// * a single string with space-separated scopes (akin to OAuth2's "scope").
func parseClaimScopes(token *jwt.Token) (map[string]bool, []string, error) {
	scopesInClaim := make(map[string]bool)
	var scopesInClaimList []string
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported claims shape")
	}
	if claims["scopes"] != nil {
		switch scopes := claims["scopes"].(type) {
		case string:
			for _, scope := range strings.Split(scopes, " ") {
				scopesInClaim[scope] = true
				scopesInClaimList = append(scopesInClaimList, scope)
			}
		case []interface{}:
			for _, scope := range scopes {
				if val, ok := scope.(string); ok {
					scopesInClaim[val] = true
					scopesInClaimList = append(scopesInClaimList, val)
				}
			}
		default:
			return nil, nil, fmt.Errorf("unsupported 'scopes' format in incoming JWT claim, was type %T", scopes)
		}
	}
	sort.Strings(scopesInClaimList)
	return scopesInClaim, scopesInClaimList, nil
}

func validateRSAKeys(rsaKeys []*rsa.PublicKey, algo, incomingToken string) (token *jwt.Token, err error) {
	for _, pubkey := range rsaKeys {
		token, err = jwt.Parse(incomingToken, func(token *jwt.Token) (interface{}, error) {
			if !strings.HasPrefix(token.Method.Alg(), algo) {
				return nil, goaJwt.ErrJWTError(fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"]))
			}
			return pubkey, nil
		})
		if err == nil {
			return
		}
	}
	return
}

func validateECDSAKeys(ecdsaKeys []*ecdsa.PublicKey, algo, incomingToken string) (token *jwt.Token, err error) {
	for _, pubkey := range ecdsaKeys {
		token, err = jwt.Parse(incomingToken, func(token *jwt.Token) (interface{}, error) {
			if !strings.HasPrefix(token.Method.Alg(), algo) {
				return nil, goaJwt.ErrJWTError(fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"]))
			}
			return pubkey, nil
		})
		if err == nil {
			return
		}
	}
	return
}

func validateHMACKeys(hmacKeys [][]byte, algo, incomingToken string) (token *jwt.Token, err error) {
	for _, key := range hmacKeys {
		token, err = jwt.Parse(incomingToken, func(token *jwt.Token) (interface{}, error) {
			if !strings.HasPrefix(token.Method.Alg(), algo) {
				return nil, goaJwt.ErrJWTError(fmt.Sprintf("Unexpected signing method: %v", token.Header["alg"]))
			}
			return key, nil
		})
		if err == nil {
			return
		}
	}
	return
}
