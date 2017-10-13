package flow

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/url"

	"github.com/JormungandrK/microservice-security/acl"
	"github.com/JormungandrK/microservice-security/chain"
	"github.com/JormungandrK/microservice-security/jwt"
	"github.com/JormungandrK/microservice-security/oauth2"
	"github.com/JormungandrK/microservice-security/saml"
	"github.com/JormungandrK/microservice-tools/config"
	"github.com/crewjam/saml/samlsp"
	"github.com/goadesign/goa"
)

type CleanupFn func()

func NewFullSecurity(conf *config.ServiceConfig, jwtSpec *goa.JWTSecurity,
	oauth2Spec *goa.OAuth2Security, samlSpec *samlsp.Middleware) (chain.SecurityChain, CleanupFn, error) {

	securityChain := chain.NewSecurityChain()

	jwtMiddleware := jwt.NewJWTSecurity(conf.SecurityConfig.KeysDir, jwtSpec)
	oauth2Middleware := oauth2.NewOAuth2Security(conf.SecurityConfig.KeysDir, oauth2Spec)

	manager, cleanup, err := acl.NewMongoDBLadonManager(&conf.DBConfig)
	if err != nil {
		return nil, nil, err
	}

	aclMiddleware, err := acl.NewACLMiddleware(manager)
	if err != nil {
		return nil, nil, err
	}

	samlMiddleware := saml.NewSAMLSecurity(samlSpec, &conf.SAMLConfig)

	securityChain.AddMiddleware(jwtMiddleware)
	securityChain.AddMiddleware(oauth2Middleware)
	securityChain.AddMiddleware(samlMiddleware)

	securityChain.AddMiddleware(chain.CheckAuth)

	securityChain.AddMiddleware(aclMiddleware)

	return securityChain, cleanup, nil
}

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

func NewSecurityFromConfig(cfg *config.ServiceConfig) (chain.SecurityChain, CleanupFn, error) {

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

	samlMiddleware, err := newSAMLSecurity(cfg.GatewayURL, &cfg.SAMLConfig)
	if err != nil {
		return nil, nil, err
	}

	manager, cleanup, err := acl.NewMongoDBLadonManager(&cfg.DBConfig)
	if err != nil {
		return nil, nil, err
	}

	aclMiddleware, err := acl.NewACLMiddleware(manager)
	if err != nil {
		return nil, nil, err
	}

	securityChain := chain.NewSecurityChain().
		AddMiddleware(jwtMiddleware).
		AddMiddleware(oauth2Middleware).
		AddMiddleware(samlMiddleware).
		AddMiddleware(chain.CheckAuth).
		AddMiddleware(aclMiddleware)

	return securityChain, cleanup, nil
}
