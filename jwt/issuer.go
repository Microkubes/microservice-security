package jwt

import (
	"fmt"

	jwtgo "github.com/dgrijalva/jwt-go"
)

type SigningMethods map[string]jwtgo.SigningMethod

var AvailableSigningMethods = SigningMethods{
	"RS256": jwtgo.SigningMethodRS256,
	"RS384": jwtgo.SigningMethodRS384,
	"RS512": jwtgo.SigningMethodRS512,
}

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
