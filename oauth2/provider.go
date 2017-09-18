package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/JormungandrK/microservice-security/jwt"
	"github.com/JormungandrK/microservice-security/tools"
	"github.com/goadesign/goa"
	uuid "github.com/satori/go.uuid"
)

// OAuth2ErrorInvalidRedirectURI is Bad Request error for invalid redirect URI
var OAuth2ErrorInvalidRedirectURI = goa.NewErrorClass("invalid_request", 400)

// OAuth2ErrorInvalidScope is Bad Request error for invalid scope requested
var OAuth2ErrorInvalidScope = goa.NewErrorClass("invalid_scope", 400)

// InternalServerError is a generic server error
var InternalServerError = goa.NewErrorClass("server_error", 500)

// OAuth2ErrorUnauthorizedClient is an error for bad client credentials
var OAuth2ErrorUnauthorizedClient = goa.NewErrorClass("unauthorized_client", 401)

// OAuth2AccessDenied is an access denied error for created auth
var OAuth2AccessDenied = goa.NewErrorClass("access_denied", 403)

// Client holds the data for a specific client (app).
// A client must firt be registered for access on the platform.
type Client struct {
	ClientID    string `json:"clientId, omitempty"`
	Name        string `json:"name, omitempty"`
	Description string `json:"description, omitempty"`
	Website     string `json:"website, omitempty"`
	Secret      string `json:"secret, omitempty"`
}

// ClientAuth is an authorization record for a specific client (app) and user.
// It holds the data for a specific client that is (or needs to be) authorized
// by a user to access some part of the platform.
type ClientAuth struct {
	ClientID    string `json:"clientId, omitempty" bson:"clientId"`
	UserID      string `json:"userId, omitempty" bson:"userId"`
	Scope       string `json:"scope, omitempty" bson:"scope"`
	Code        string `json:"code, omitempty" bson:"code"`
	GeneratedAt int64  `json:"generatedAt, omitempty" bson:"generatedAt"`
	UserData    string `json:"userData, omitempty" bson:"userData"`
	RedirectURI string `json:"redirectUri, omitempty" bson:"redirectUri"`
	Confirmed   bool   `json:"confirmed, omitempty" bson:"confirmed"`
}

// ClientService is an interface that defines the access to a Client and ClientAuth.
type ClientService interface {

	// GetClient retrieves a Client by its ID.
	GetClient(clientID string) (*Client, error)

	// VerifyClientCredentials verfies that there is a registered Client with the specified client ID and client secret.
	// It returns the actual Client data if the credentials are valid, or nil if there is no such client.
	VerifyClientCredentials(clientID, clientSecret string) (*Client, error)

	// SaveClientAuth stores a ClientAuth.
	SaveClientAuth(clientAuth *ClientAuth) error

	// GetClientAuth retrieves a ClientAuth for the specified client ID and a generated random code for verification.
	GetClientAuth(clientID, code string) (*ClientAuth, error)

	// GetClientAuthForUser retrieves a ClientAuth for a Client and User.
	// Used when is situations where the access code is still not generated.
	GetClientAuthForUser(userID, clientID string) (*ClientAuth, error)

	// ConfirmClientAuth updates the Confirmed field (sets it to true).
	// Used to update the client auth once the user has accepted the client to access the data.
	ConfirmClientAuth(userID, clientID string) (*ClientAuth, error)

	// UpdateUserData updates the ClientAuth with the full user data.
	// This is techincally a workaround since the goa-oauth2 Provider does not take
	// into account the user in the access_grant flow.
	UpdateUserData(clientID, code, userID, userData string) error

	// DeleteClientAuth deletes the ClientAuth.
	// If you never call this, the ClientAuth should expire automatically after a certain period.
	DeleteClientAuth(clientID, code string) error
}

// User holds the user data.
type User struct {
	ID            string   `json:"id, omitempty"`
	Username      string   `json:"username, omitempty"`
	Email         string   `json:"email, omitempty"`
	Roles         []string `json:"roles, omitempty"`
	Organizations []string `json:"organizations, omitempty"`
	ExternalID    string   `json:"externalId, omitempty"`
}

// UserService defines an interface for verification of the user credentials.
// This is used in the access_grant flow, to login the user and then prompt it
// for confirmation about authorizing the client to access the services on the platform.
type UserService interface {
	// VerifyUser verifies the credentials (username and password) and retrieves a
	// User if the credentials are valid.
	VerifyUser(username, password string) (*User, error)
}

// AuthToken holds the data for oauth2 token.
type AuthToken struct {
	// AccessToken is the actual value of the access token.
	AccessToken string `json:"accessToken, omitempty" bson:"accessToken"`

	// RefreshToken  holds the refresh token value.
	RefreshToken string `json:"refreshToken, omitempty" bson:"refreshToken"`

	// Unix timestamp of the time when the access token was issued.
	IssuedAt int64 `json:"issuedAt, omitempty" bson:"issuedAt"`

	// ValidFor is the time duration for which this token is valid. Expressed in milliseconds.
	ValidFor int `json:"validFor, omitempty" bson:"validFor"`

	// Scope is the scope for which this access token is valid.
	Scope string `json:"scope, omitempty" bson:"scope"`

	// ClientID is the reference to the client for which this token has been issued.
	ClientID string `json:"clientId, omitempty" bson:"clientId"`

	// UserID is the reference to the user for which this token has been issued.
	UserID string `json:"userId, omitempty" bson:"userId"`
}

// TokenService defines the interface for managing OAuth2 Tokens.
type TokenService interface {

	// SaveToken saves the token data to the backend.
	SaveToken(token AuthToken) error

	// GetToken retrieves the OAuth2Token for a refreshToken.
	GetToken(refreshToken string) (*AuthToken, error)

	// GetTokenForClient looks up an OAuth2Token for a specific client and user.
	// There should be only one such token.
	GetTokenForClient(userID, clientID string) (*AuthToken, error)
}

// AuthProvider holds the data for implementing the oauth2.Provider interface.
type AuthProvider struct {
	ClientService
	UserService
	TokenService
	tools.KeyStore
	SigningMethod             string
	AuthCodeLength            int
	RefreshTokenLength        int
	AccessTokenValidityPeriod int
	ProviderName              string
}

// Authorize performs the authorization of a client and generates basic ClientAuth.
func (provider *AuthProvider) Authorize(clientID, scope, redirectURI string) (code string, err error) {
	client, err := provider.ClientService.GetClient(clientID)
	if err != nil {
		return "", OAuth2ErrorUnauthorizedClient("invalid_client")
	}
	if err = CompareRedirectURI(client.Website, redirectURI); err != nil {
		return "", OAuth2ErrorInvalidRedirectURI("invalid_request")
	}
	code, err = GenerateRandomCode(provider.AuthCodeLength)
	if err != nil {
		return "", InternalServerError("server_error")
	}
	err = provider.ClientService.SaveClientAuth(&ClientAuth{
		ClientID:    clientID,
		Code:        code,
		GeneratedAt: time.Now().Unix(),
		Scope:       scope,
		RedirectURI: redirectURI,
		// Note that the UserData field MUST be populated afterwards, in a special flow
		// with user interaction (usually after the authorize has completed and the resource
		// owner has authorized the client. At that point we have the user logged in and we serialize the user data)
	})
	if err != nil {
		return "", InternalServerError("unauthorized_client")
	}
	return code, nil
}

// Exchange exchanges the confimed ClientAuth for an access token and refresh token.
func (provider *AuthProvider) Exchange(clientID, code, redirectURI string) (refreshToken, accessToken string, expiresIn int, err error) {
	clientAuth, err := provider.ClientService.GetClientAuth(clientID, code)
	if err != nil {
		return "", "", 0, InternalServerError("Failed to verify client authentication", err)
	}
	if clientAuth == nil || clientAuth.UserData == "" {
		return "", "", 0, OAuth2AccessDenied("client not authorized")
	}

	client, err := provider.ClientService.GetClient(clientID)
	if err != nil {
		return "", "", 0, InternalServerError("Unable to verify client at this time")
	}
	if client == nil {
		return "", "", 0, OAuth2AccessDenied("client not registered")
	}

	if err = CompareRedirectURI(client.Website, redirectURI); err != nil {
		return "", "", 0, OAuth2ErrorInvalidRedirectURI(err)
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

// generateAccessToken generates new access token as JWT token with encoded user data and standard JWT claims.
// The generated access token is self contained - holds all data needed to authenticate and authorize the user by APIs.
func (provider *AuthProvider) generateAccessToken(userData map[string]interface{}, clientID, scope string) (string, error) {
	key, err := provider.KeyStore.GetPrivateKey()
	if err != nil {
		return "", err
	}
	// Remap JWT standard claims
	userData["jti"] = uuid.NewV4().String()
	userData["iss"] = provider.ProviderName
	userData["exp"] = time.Now().Add(time.Duration(provider.AccessTokenValidityPeriod) * time.Millisecond).Unix()
	userData["iat"] = time.Now().Unix()

	userData["nbf"] = 0
	userData["sub"] = clientID
	userData["scopes"] = scope

	token, err := jwt.SignToken(userData, provider.SigningMethod, key)
	return token, err
}

func (provider *AuthProvider) generateOAuthToken(clientID, scope string, userData map[string]interface{}) (*AuthToken, error) {
	accessToken, err := provider.generateAccessToken(userData, clientID, scope)
	if err != nil {
		return nil, err
	}

	refreshToken, err := GenerateRandomCode(provider.RefreshTokenLength)
	if err != nil {
		return nil, err
	}

	oauth2Token := AuthToken{
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

// Refresh exchnages a refresh token for a new access token.
func (provider *AuthProvider) Refresh(refreshToken, scope string) (newRefreshToken, accessToken string, expiresIn int, err error) {
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

	tokenParts := strings.Split(oauth2Token.AccessToken, ".")
	if len(tokenParts) != 3 {
		return "", "", 0, InternalServerError("The access token is in invalid format")
	}

	jwtClaims, err := base64.StdEncoding.DecodeString(tokenParts[1])
	if err != nil {
		return "", "", 0, InternalServerError("Failed to decode the access token", err)
	}

	err = json.Unmarshal(jwtClaims, &userData)
	if err != nil {
		return "", "", 0, InternalServerError("Failed to read the access token", err)
	}

	oauth2Token, err = provider.generateOAuthToken(oauth2Token.ClientID, oauth2Token.Scope, userData)

	if err != nil {
		return "", "", 0, InternalServerError("Failed to generate token pair", err)
	}

	return oauth2Token.RefreshToken, oauth2Token.AccessToken, oauth2Token.ValidFor, nil
}

// Authenticate checks the client credentials.
func (provider *AuthProvider) Authenticate(clientID, clientSecret string) error {
	client, err := provider.ClientService.VerifyClientCredentials(clientID, clientSecret)
	if err != nil {
		return InternalServerError(err)
	}
	if client == nil {
		return fmt.Errorf("No client with supplied credentials")
	}
	return nil
}

// GenerateRandomCode generates a cryptographically strong random string with the specified length.
func GenerateRandomCode(n int) (string, error) {
	buff := make([]byte, n*3/4+1) // base64 string will have approximately 4/3 more chars than the buffer byte length.
	_, err := rand.Read(buff)
	if err != nil {
		return "", err
	}
	code := base64.StdEncoding.EncodeToString(buff)

	return code[0:n], nil
}

// CompareRedirectURI compares the registered redirect URI with a provided one.
func CompareRedirectURI(registered, provided string) error {
	// compare scheme + host + port
	var registeredURL *url.URL
	var providedURL *url.URL
	var regErr error
	var provErr error

	registeredURL, regErr = url.Parse(registered)
	providedURL, provErr = url.Parse(provided)

	if regErr != nil && provErr != nil {
		// both are not valid URLs, so just compare the value
		if registered == provided {
			return nil
		}
		return fmt.Errorf("redirect URI value differs from the registered")
	} else if regErr == nil && provErr == nil {
		// both are valid URLs

		// compare scheme + host:port
		if registeredURL.Scheme == providedURL.Scheme &&
			registeredURL.Host == providedURL.Host {
			return nil
		}
		return fmt.Errorf("redirect URL different than the registered")
	}
	// whatever we got as redirect uri, it cannot be the same with the
	// registered one at this point. One is valid URL, the other isn't.

	return fmt.Errorf("redirect URI is not valid")

}
