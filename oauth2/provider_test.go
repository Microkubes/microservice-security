package oauth2

// import (
// 	"crypto/rand"
// 	"crypto/rsa"
// 	"fmt"
// 	"strings"
// 	"testing"
// 	"time"
// )

// type DummyClientService struct {
// 	Clients map[string]*Client
// 	Auths   map[string]*ClientAuth
// }

// func (d *DummyClientService) GetClient(clientID string) (*Client, error) {
// 	cl, ok := d.Clients[clientID]
// 	if !ok {
// 		return nil, fmt.Errorf("Not found")
// 	}
// 	return cl, nil
// }

// func (d *DummyClientService) VerifyClientCredentials(clientID, clientSecret string) (*Client, error) {
// 	cl, ok := d.Clients[clientID]
// 	if !ok {
// 		return nil, fmt.Errorf("Invalid credentials")
// 	}
// 	if cl.Secret != clientSecret {
// 		return nil, nil
// 	}
// 	return cl, nil
// }

// func (d *DummyClientService) SaveClientAuth(clientAuth *ClientAuth) error {
// 	key := fmt.Sprintf("%s-%s", clientAuth.ClientID, clientAuth.Code)
// 	d.Auths[key] = clientAuth

// 	return nil
// }

// func (d *DummyClientService) GetClientAuth(clientID, code string) (*ClientAuth, error) {
// 	key := fmt.Sprintf("%s-%s", clientID, code)
// 	ca, _ := d.Auths[key]
// 	return ca, nil
// }

// func (d *DummyClientService) GetClientAuthForUser(userID, clientID string) (*ClientAuth, error) {
// 	for key, ca := range d.Auths {
// 		if strings.HasPrefix(key, clientID) {
// 			if ca.UserID == userID {
// 				return ca, nil
// 			}
// 		}
// 	}
// 	return nil, nil
// }

// func (d *DummyClientService) ConfirmClientAuth(userID, clientID string) (*ClientAuth, error) {
// 	ca, _ := d.GetClientAuthForUser(userID, clientID)
// 	if ca != nil {
// 		ca.Confirmed = true
// 		return ca, nil
// 	}
// 	return nil, nil
// }

// func (d *DummyClientService) UpdateUserData(clientID, code, userID, userData string) error {
// 	key := fmt.Sprintf("%s-%s", clientID, code)
// 	ca, ok := d.Auths[key]
// 	if !ok {
// 		return fmt.Errorf("No such authentication")
// 	}
// 	ca.UserData = userData
// 	ca.UserID = userID
// 	return nil
// }

// func (d *DummyClientService) DeleteClientAuth(clientID, code string) error {
// 	key := fmt.Sprintf("%s-%s", clientID, code)
// 	_, ok := d.Auths[key]
// 	if ok {
// 		d.Auths[key] = nil
// 	}
// 	return nil
// }

// func NewMockClientService() *DummyClientService {
// 	return &DummyClientService{
// 		Clients: map[string]*Client{},
// 		Auths:   map[string]*ClientAuth{},
// 	}
// }

// type DummyTokenService struct {
// 	Tokens map[string]*AuthToken
// }

// func (d *DummyTokenService) SaveToken(token AuthToken) error {
// 	d.Tokens[token.RefreshToken] = &token
// 	return nil
// }

// func (d *DummyTokenService) GetToken(refreshToken string) (*AuthToken, error) {
// 	if token, ok := d.Tokens[refreshToken]; ok {
// 		return token, nil
// 	}
// 	return nil, nil
// }

// func (d *DummyTokenService) GetTokenForClient(userID, clientID string) (*AuthToken, error) {
// 	return nil, nil
// }

// type DummyKeyStore struct {
// 	PrivateKey interface{}
// }

// // GetPrivateKey returns the default private key used for signing.
// func (d *DummyKeyStore) GetPrivateKey() (interface{}, error) {
// 	if d.PrivateKey == nil {
// 		return nil, fmt.Errorf("No default key")
// 	}
// 	return d.PrivateKey, nil
// }

// // GetPrivateKeyByName gets a private key by name
// func (d *DummyKeyStore) GetPrivateKeyByName(keyName string) (interface{}, error) {
// 	if d.PrivateKey == nil {
// 		return nil, fmt.Errorf("No default key")
// 	}
// 	if keyName != "default" {
// 		return nil, fmt.Errorf("No key with that name")
// 	}
// 	return d.PrivateKey, nil
// }

// func NewDummyKeyStore() *DummyKeyStore {
// 	key, err := rsa.GenerateKey(rand.Reader, 2048)
// 	if err != nil {
// 		panic(err)
// 	}
// 	return &DummyKeyStore{
// 		PrivateKey: key,
// 	}
// }

// func NewMockOAuth2Provider(clients []*Client) *AuthProvider {
// 	cs := NewMockClientService()
// 	for _, client := range clients {
// 		cs.Clients[client.ClientID] = client
// 	}
// 	return &AuthProvider{
// 		ClientService: cs,
// 		TokenService: &DummyTokenService{
// 			Tokens: map[string]*AuthToken{},
// 		},
// 		KeyStore:                  NewDummyKeyStore(),
// 		SigningMethod:             "RS512",
// 		AuthCodeLength:            10,
// 		RefreshTokenLength:        30,
// 		AccessTokenValidityPeriod: 3600 * 1000,
// 	}
// }

// type MockUser struct {
// 	User
// 	Password string
// }

// type DummyUserService struct {
// 	Users map[string]*MockUser
// }

// func (d *DummyUserService) VerifyUser(username, password string) (*User, error) {
// 	if user, ok := d.Users[username]; ok {
// 		if user.Password == password {
// 			return &user.User, nil
// 		}
// 	}
// 	return nil, nil
// }

// func TestGenerateRandomCode(t *testing.T) {
// 	for i := 1; i < 35; i++ {
// 		code, err := GenerateRandomCode(i)
// 		t.Logf("%d: %s", i, code)
// 		if err != nil {
// 			t.Fatal(err)
// 		}
// 		if len(code) != i {
// 			t.Fatal("Expected a string with length ", i)
// 		}
// 	}
// }

// func getMockedProvider(t *testing.T) *AuthProvider {
// 	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	return &AuthProvider{
// 		ClientService: &DummyClientService{
// 			Auths: map[string]*ClientAuth{},
// 			Clients: map[string]*Client{
// 				"001": &Client{
// 					ClientID: "001",
// 					Name:     "test-client",
// 					Secret:   "xyz",
// 					Website:  "http://example.com:8080",
// 				},
// 			},
// 		},
// 		TokenService: &DummyTokenService{
// 			Tokens: map[string]*AuthToken{},
// 		},
// 		UserService: &DummyUserService{
// 			Users: map[string]*MockUser{
// 				"10001": &MockUser{
// 					User: User{
// 						Email:         "user@example.com",
// 						ID:            "10001",
// 						Roles:         []string{"user"},
// 						Username:      "user",
// 						Organizations: []string{"org1", "org2"},
// 					},
// 					Password: "pass",
// 				},
// 			},
// 		},
// 		KeyStore: &DummyKeyStore{
// 			PrivateKey: privkey,
// 		},
// 		SigningMethod:             "RS512",
// 		AuthCodeLength:            10,
// 		RefreshTokenLength:        20,
// 		AccessTokenValidityPeriod: 2000,
// 		ProviderName:              "unit-test-dummy",
// 	}
// }

// func TestAuthorize(t *testing.T) {

// 	provider := getMockedProvider(t)

// 	authCode, err := provider.Authorize("001", "api:read", "http://example.com:8080")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if authCode == "" {
// 		t.Fatal("Expected an auth code")
// 	}

// 	t.Log("Auth Code:", authCode)

// }

// func TestAuthenticate(t *testing.T) {
// 	provider := getMockedProvider(t)

// 	err := provider.Authenticate("001", "xyz")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// }

// func TestExchange(t *testing.T) {
// 	provider := getMockedProvider(t)
// 	clientSvcMock := provider.ClientService.(*DummyClientService)
// 	clientSvcMock.Auths["001-authcode"] = &ClientAuth{
// 		ClientID:    "001",
// 		Code:        "authcode",
// 		Confirmed:   true,
// 		GeneratedAt: time.Now().Unix(),
// 		RedirectURI: "http://example.com:8080",
// 		Scope:       "api:read",
// 		UserData:    "{\"userId\":\"10001\"}",
// 		UserID:      "10001",
// 	}
// 	refreshToken, accessToken, validityPeriod, err := provider.Exchange("001", "authcode", "http://example.com:8080")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if refreshToken == "" {
// 		t.Fatal("Expected refresh token to be generated")
// 	}
// 	if accessToken == "" {
// 		t.Fatal("Expected access token to be generated")
// 	}
// 	if validityPeriod <= 0 {
// 		t.Fatal("Token should be valid for more than 0ms")
// 	}
// }

// func TestRefresh(t *testing.T) {
// 	provider := getMockedProvider(t)

// 	mockTockenService := provider.TokenService.(*DummyTokenService)
// 	mockTockenService.Tokens["refresh-token-code"] = &AuthToken{
// 		AccessToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcklkIjoiMTAwMDEiLCJyb2xlcyI6InVzZXIiLCJvcmdhbml6YXRpb25zIjoib3JnMSJ9.f6wxZDcq4GNSS86E6aTFERvznmm3-Zi--ujtUwFH32I",
// 		ClientID:     "001",
// 		IssuedAt:     time.Now().Truncate(time.Duration(provider.AccessTokenValidityPeriod-100) * time.Millisecond).Unix(),
// 		RefreshToken: "refresh-token-code",
// 		Scope:        "api:read",
// 		UserID:       "10001",
// 		ValidFor:     provider.AccessTokenValidityPeriod,
// 	}
// 	refreshToken, accessToken, validityPeriod, err := provider.Refresh("refresh-token-code", "api:read")
// 	if err != nil {
// 		t.Fatal(err)
// 	}
// 	if refreshToken == "" {
// 		t.Fatal("Expected refresh token to be generated")
// 	}
// 	if accessToken == "" {
// 		t.Fatal("Expected access token to be generated")
// 	}
// 	if validityPeriod <= 0 {
// 		t.Fatal("Token should be valid for more than 0ms")
// 	}
// }
