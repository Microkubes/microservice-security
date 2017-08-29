package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"time"

	"github.com/JormungandrK/microservice-security/jwt"
	"github.com/JormungandrK/microservice-security/tools"
	"github.com/goadesign/goa"
)

var OAuth2ErrorInvalidRedirectURI = goa.NewErrorClass("invalid_request", 400)
var OAuth2ErrorInvalidScope = goa.NewErrorClass("invalid_scope", 400)
var InternalServerError = goa.NewErrorClass("server_error", 500)
var OAuth2ErrorUnauthorizedClient = goa.NewErrorClass("unauthorized_client", 401)
var OAuth2AccessDenied = goa.NewErrorClass("access_denied", 403)

type Client struct {
	ClientID    string
	Name        string
	Description string
	Website     string
}

type ClientAuth struct {
	ClientId    string
	Scope       string
	Code        string
	GeneratedAt int64
	UserData    string
	RedirectURI string
}

type ClientService interface {
	GetClient(clientID string) (*Client, error)
	VerifyClientCredentials(clientID, clientSecret string) (*Client, error)
	SaveClientAuth(clientAuth *ClientAuth) error
	GetClientAuth(clientID, code string) (*ClientAuth, error)
	UpdateUserData(clientID, code, userData string) error
	DeleteClientAuth(clientID, code string) error
}

type User struct {
}

type UserService interface {
}

type OAuth2Token struct {
	AccessToken  string
	RefreshToken string
	IssuedAt     int64
	ValidFor     int
	Scope        string
	ClientID     string
}

type TokenService interface {
	SaveToken(token OAuth2Token) error
	GetToken(refreshToken string) (*OAuth2Token, error)
}

type OAuth2Provider struct {
	ClientService
	UserService
	TokenService
	tools.KeyStore
	SigningMethod             string
	AuthCodeLength            int
	RefreshTokenLength        int
	AccessTokenValidityPeriod int
}

func (provider *OAuth2Provider) Authorize(clientID, scope, redirectURI string) (code string, err error) {
	client, err := provider.ClientService.GetClient(clientID)
	if err != nil {
		return "", OAuth2ErrorUnauthorizedClient("Invalid Client ID")
	}
	if client.Website != redirectURI {
		return "", OAuth2ErrorInvalidRedirectURI("invalid redirect URI")
	}
	code, err = GenerateRandomCode(provider.AuthCodeLength)
	if err != nil {
		return "", InternalServerError("failed to generate authorization code")
	}
	err = provider.SaveClientAuth(&ClientAuth{
		ClientId:    clientID,
		Code:        code,
		GeneratedAt: time.Now().Unix(),
		Scope:       scope,
		RedirectURI: redirectURI,
		// Note that the UserData field MUST be populated afterwards, in a special flow
		// with user interaction (usually after the authorize has completed and the resource
		// owner has authorized the client. At that point we have the user logged in and we serialize the user data)
	})
	if err != nil {
		return "", InternalServerError("Failed to authorize client")
	}
	return code, nil
}

func (provider *OAuth2Provider) Exchange(clientID, code, redirectURI string) (refreshToken, accessToken string, expiresIn int, err error) {
	// 1. Find ClientAuth
	// 2. Extract UserData (JSON encoded string of the user data)
	// 3. Sign JWT token with the user data
	// 4. Generate Refresh token (crypto-strong random string)
	// 5. Generate the Token entry (JWT + Refresh token + clientId + timestamp)
	// 6. Store the token
	// 7. Clean up the Client Authroization
	clientAuth, err := provider.ClientService.GetClientAuth(clientID, code)
	if err != nil {
		return "", "", 0, InternalServerError("Failed to verify client authentication", err)
	}
	if clientAuth == nil || clientAuth.UserData == "" {
		return "", "", 0, OAuth2AccessDenied("client not authorized")
	}

	userData := map[string]interface{}{}

	if err = json.Unmarshal([]byte(clientAuth.UserData), &userData); err != nil {
		return "", "", 0, InternalServerError("Failed to read user data", err)
	}

	oauth2Token, err := provider.generateOAuthToken(clientID, clientAuth.Scope, userData)
	if err != nil {
		return "", "", 0, InternalServerError("Failed to generate access token and refresh token", err)
	}

	err = provider.ClientService.DeleteClientAuth(clientID, code)

	if err != nil {
		return "", "", 0, InternalServerError(err)
	}

	return oauth2Token.RefreshToken, oauth2Token.AccessToken, oauth2Token.ValidFor, nil
}

func (provider *OAuth2Provider) generateAccessToken(userData map[string]interface{}) (string, error) {
	key, err := provider.KeyStore.GetPrivateKey()
	if err != nil {
		return "", err
	}
	// TODO: Remap JWT standard claims
	token, err := jwt.SignToken(userData, provider.SigningMethod, key)
	return token, err
}

func (provider *OAuth2Provider) generateOAuthToken(clientID, scope string, userData map[string]interface{}) (*OAuth2Token, error) {
	accessToken, err := provider.generateAccessToken(userData)
	if err != nil {
		return nil, err
	}

	refreshToken, err := GenerateRandomCode(provider.RefreshTokenLength)
	if err != nil {
		return nil, err
	}

	oauth2Token := OAuth2Token{
		AccessToken:  accessToken,
		ClientID:     clientID,
		IssuedAt:     time.Now().Unix(),
		RefreshToken: refreshToken,
		Scope:        scope,
		ValidFor:     provider.AccessTokenValidityPeriod,
	}

	err = provider.TokenService.SaveToken(oauth2Token)
	return &oauth2Token, err
}

func (provider *OAuth2Provider) Refresh(refreshToken, scope string) (newRefreshToken, accessToken string, expiresIn int, err error) {
	oauth2Token, err := provider.TokenService.GetToken(refreshToken)
	if err != nil {
		return "", "", 0, InternalServerError("Failed to verify refresh token", err)
	}
	if oauth2Token == nil {
		return "", "", 0, OAuth2AccessDenied("Invalid refresh token")
	}

	if oauth2Token.Scope != scope {
		return "", "", 0, OAuth2ErrorInvalidScope("invalid_scope")
	}

	userData := map[string]interface{}{}
	err = json.Unmarshal([]byte(oauth2Token.AccessToken), &userData)
	if err != nil {
		return "", "", 0, InternalServerError("Failed to read the access token", err)
	}

	oauth2Token, err = provider.generateOAuthToken(oauth2Token.ClientID, oauth2Token.Scope, userData)

	if err != nil {
		return "", "", 0, InternalServerError("Failed to generate token pair", err)
	}

	return oauth2Token.RefreshToken, oauth2Token.AccessToken, oauth2Token.ValidFor, nil
}

func (provider *OAuth2Provider) Authenticate(clientID, clientSecret string) error {
	return nil
}

func GenerateRandomCode(n int) (string, error) {
	buff := make([]byte, n*3/4+1) // base64 string will have approximately 4/3 more chars than the buffer byte length.
	_, err := rand.Read(buff)
	if err != nil {
		return "", err
	}
	code := base64.StdEncoding.EncodeToString(buff)

	return code[0:n], nil
}
