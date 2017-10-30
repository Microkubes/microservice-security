package flow

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log"
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

func newSAMLSecurity(gatewayURL string, conf *config.SAMLConfig) (chain.SecurityChainMiddleware, *samlsp.Middleware, error) {
	keyPair, err := tls.LoadX509KeyPair(conf.CertFile, conf.KeyFile)
	if err != nil {
		panic(err)
	}

	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		panic(err)
	}

	u, err := url.Parse(gatewayURL)
	if err != nil {
		panic(err)
	}

	rootURL, err := url.Parse(fmt.Sprintf("http://%s:8000/users", u.Hostname()))
	if err != nil {
		panic(err)
	}

	idpMetadataURL, err := url.Parse(fmt.Sprintf("http://%s:8000/saml/idp/metadata", u.Hostname()))
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
		return nil, nil, err
	}
	return saml.NewSAMLSecurity(samlSP, conf), samlSP, nil
}

// NewSecurityFromConfig sets up a full secrity chain froma a given service configuration.
func NewSecurityFromConfig(cfg *config.ServiceConfig) (chain.SecurityChain, CleanupFn, error) {
	securityChain := chain.NewSecurityChain()
	if cfg.Disable {
		log.Println("WARN: Security is disabled. Please check your configuration.")
		return securityChain, func() {}, nil
	}

	managerCleanup := func() {}
	samlCleanup := func() {}

	cleanup := func() {
		managerCleanup()
		samlCleanup()
	}

	if cfg.SecurityConfig.JWTConfig != nil {
		jwtSpec := &goa.JWTSecurity{
			Name:        "Authorization",
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
		samlMiddleware, spMiddleware, err := newSAMLSecurity(cfg.GatewayURL, cfg.SAMLConfig)
		if err != nil {
			return nil, cleanup, err
		}

		sc, err := saml.RegisterSP(spMiddleware, cfg.SAMLConfig)
		if err != nil {
			return nil, cleanup, err
		}
		samlCleanup = sc

		securityChain.AddMiddleware(samlMiddleware)
	}

	if cfg.SecurityConfig.JWTConfig == nil &&
		cfg.SecurityConfig.OAuth2Config == nil &&
		cfg.SecurityConfig.SAMLConfig == nil {
		// No security defined
		return securityChain, cleanup, nil
	}

	securityChain.AddMiddleware(chain.CheckAuth)

	if !cfg.ACLConfig.Disable {
		manager, mc, err := acl.NewMongoDBLadonManager(&cfg.DBConfig)
		if err != nil {
			return nil, cleanup, err
		}
		managerCleanup = mc

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

		if cfg.ACLConfig.Policies != nil {
			for _, policy := range cfg.ACLConfig.Policies {
				ladonPolicy := &ladon.DefaultPolicy{
					ID:          policy.ID,
					Actions:     policy.Actions,
					Description: policy.Description,
					Effect:      policy.Effect,
					Resources:   policy.Resources,
					Subjects:    policy.Subjects,
				}
				if policy.Conditions != nil {
					conditions, e := conditionsFromConfig(policy.Conditions)
					if e != nil {
						return nil, cleanup, e
					}
					ladonPolicy.Conditions = conditions
				}
				e := addOrUpdatePolicy(ladonPolicy, manager)
				if e != nil {
					return nil, cleanup, e
				}
			}
		}

		aclMiddleware, err := acl.NewACLMiddleware(manager)
		if err != nil {
			return nil, cleanup, err
		}
		securityChain.AddMiddleware(aclMiddleware)
	}

	return securityChain, cleanup, nil
}

func addOrUpdatePolicy(policy ladon.Policy, manager *acl.MongoDBLadonManager) error {
	existing, err := manager.Get(policy.GetID())
	if err != nil {
		return err
	}

	authObj := auth.Auth{
		Username: "system",
		UserID:   "system",
		Roles:    []string{"system"},
	}
	if existing != nil {
		return manager.Update(policy)
	}
	return manager.CreateWithAuth(policy, &authObj)
}

func conditionsFromConfig(conds map[string]interface{}) (ladon.Conditions, error) {
	ladonConditions := ladon.Conditions{}

	serConds, err := json.Marshal(conds)
	if err != nil {
		return nil, err
	}

	err = ladonConditions.UnmarshalJSON(serConds)

	return ladonConditions, err
}
