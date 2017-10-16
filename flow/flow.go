package flow

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"

	"github.com/JormungandrK/microservice-security/acl"
	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/chain"
	"github.com/JormungandrK/microservice-security/jwt"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/JormungandrK/microservice-security/saml"
	"github.com/JormungandrK/microservice-tools/config"
	"github.com/crewjam/saml/samlsp"
	"github.com/goadesign/goa"
	"github.com/ory/ladon"
)

// CleanupFn defines a function used for cleanup. Usially you would like to defer this function
// for after the whole process is done and you need to clen up before shutting down.
type CleanupFn func()

func newSAMLSecurity(gatewayURL string, conf *config.SAMLConfig) (chain.SecurityChainMiddleware, error) {
	keyPair, err := tls.LoadX509KeyPair(conf.CertFile, conf.KeyFile)
	if err != nil {
		panic(err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	rootURL, err := url.Parse(fmt.Sprintf("%s/user-profile", gatewayURL))
	if err != nil {
		panic(err)
	}

	idpMetadataURL, err := url.Parse(fmt.Sprintf("%s/saml/idp/metadata", gatewayURL))
	if err != nil {
		panic(err)
	}

	samlSP, err := samlsp.New(samlsp.Options{
		IDPMetadataURL: idpMetadataURL,
		URL:            *rootURL,
		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate:    keyPair.Leaf,
	})
	if err != nil {
		return nil, err
	}
	return saml.NewSAMLSecurity(samlSP, conf), nil
}

// NewSecurityFromConfig sets up a full secrity chain froma a given service configuration.
func NewSecurityFromConfig(cfg *config.ServiceConfig) (chain.SecurityChain, CleanupFn, error) {
	securityChain := chain.NewSecurityChain()

	if cfg.SecurityConfig.JWTConfig != nil {
		jwtSpec := &goa.JWTSecurity{
			Name:        cfg.JWTConfig.Name,
			Description: cfg.JWTConfig.Description,
			In:          goa.LocHeader,
			Scopes: map[string]string{
				"api:read":  "Read API resource",
				"api:write": "Write API resource",
			},
		}

		jwtMiddleware := jwt.NewJWTSecurity(cfg.SecurityConfig.KeysDir, jwtSpec)
		securityChain.AddMiddleware(jwtMiddleware)
	}

	if cfg.SecurityConfig.OAuth2Config != nil {
		oauth2Spec := &goa.OAuth2Security{
			AuthorizationURL: cfg.OAuth2Config.AuthorizationURL,
			TokenURL:         cfg.OAuth2Config.TokenURL,
			Flow:             "accessCode",
			Description:      cfg.OAuth2Config.Description,
			Scopes: map[string]string{
				"api:read":  "Read API resource",
				"api:write": "Write API resource",
			},
		}

		oauth2Middleware := oauth2.NewOAuth2Security(cfg.SecurityConfig.KeysDir, oauth2Spec)
		securityChain.AddMiddleware(oauth2Middleware)
	}

	if cfg.SecurityConfig.SAMLConfig != nil {
		samlMiddleware, err := newSAMLSecurity(cfg.GatewayURL, cfg.SAMLConfig)
		if err != nil {
			return nil, func() {}, err
		}
		securityChain.AddMiddleware(samlMiddleware)
	}

	if cfg.SecurityConfig.JWTConfig == nil &&
		cfg.SecurityConfig.OAuth2Config == nil &&
		cfg.SecurityConfig.SAMLConfig == nil {
		// No security defined
		return securityChain, func() {}, nil
	}

	manager, cleanup, err := acl.NewMongoDBLadonManager(&cfg.DBConfig)
	if err != nil {
		return nil, func() {}, err
	}

	// add default "system" policies
	err = addOrUpdatePolicy(&ladon.DefaultPolicy{
		ID:          "system-access",
		Actions:     []string{"api:read", "api:write"},
		Description: "Default System level access to resources",
		Effect:      ladon.AllowAccess,
		Resources:   []string{"<.+>"},   // all resources
		Subjects:    []string{"system"}, // only system
	}, manager)
	if err != nil {
		panic(err)
	}

	aclMiddleware, err := acl.NewACLMiddleware(manager)
	if err != nil {
		return nil, func() {}, err
	}

	securityChain.
		AddMiddleware(chain.CheckAuth).
		AddMiddleware(aclMiddleware)

	return securityChain, cleanup, nil
}

func addOrUpdatePolicy(policy ladon.Policy, manager *acl.MongoDBLadonManager) error {
	existing, err := manager.Get(policy.GetID())
	if err != nil {
		return err
	}
	if existing != nil {
		return nil
	}
	authObj := auth.Auth{
		Username: "system",
		UserID:   "system",
		Roles:    []string{"system"},
	}
	return manager.CreateWithAuth(policy, &authObj)
}
