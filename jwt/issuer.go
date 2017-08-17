package jwt

import (
	"fmt"

	jwtgo "github.com/dgrijalva/jwt-go"
)

// SigningMethods is a map mapping from a signing method name to an actual SigningMethod
type SigningMethods map[string]jwtgo.SigningMethod

// AvailableSigningMethods holds the supported signing methods.
var AvailableSigningMethods = SigningMethods{
	"RS256": jwtgo.SigningMethodRS256,
	"RS384": jwtgo.SigningMethodRS384,
	"RS512": jwtgo.SigningMethodRS512,
}

// SignToken singns a JWT token with the given claims using the provided private key with the signingMethod.
func SignToken(claims map[string]interface{}, signingMethod string, key interface{}) (string, error) {
	method, ok := AvailableSigningMethods[signingMethod]
	if !ok {
		return "", fmt.Errorf("Unsupported sign method %s", signingMethod)
	}
	token := jwtgo.New(method)
	mapClaims := jwtgo.MapClaims{}

	for k, v := range claims {
		mapClaims[k] = v
	}

	token.Claims = mapClaims

	signedToken, err := token.SignedString(key)
	return signedToken, err
}
