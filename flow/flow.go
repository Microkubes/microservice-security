package flow

import (
	"encoding/json"
	"log"

	"github.com/Microkubes/microservice-security/tools"

	"github.com/Microkubes/microservice-security/acl"
	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-security/chain"
	"github.com/Microkubes/microservice-security/jwt"
	"github.com/Microkubes/microservice-tools/config"
	"github.com/ory/ladon"
)

// CleanupFn defines a function used for cleanup. Usually you would like to defer this function
// for after the whole process is done and you need to clean up before shutting down.
type CleanupFn func()

// ConfiguredSecurity holds the entities of the fully configured security. It holds
// the SecurityChain, the KeyStore, ACLManager (if configured) and optional cleanup function.
type ConfiguredSecurity struct {
	Chain      chain.SecurityChain
	KeyStore   tools.KeyStore
	ACLManager *acl.BackendLadonManager
	Cleanup    CleanupFn
}

// func newSAMLSecurity(gatewayURL string, conf *config.SAMLConfig) (chain.SecurityChainMiddleware, *samlsp.Middleware, error) {
// 	keyPair, err := tls.LoadX509KeyPair(conf.CertFile, conf.KeyFile)
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	rootURL, err := url.Parse(fmt.Sprintf("%s", conf.RootURL))
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	idpMetadataURL, err := url.Parse(fmt.Sprintf("%s/saml/idp/metadata", gatewayURL))
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	samlSP, err := samlsp.New(samlsp.Options{
// 		IDPMetadataURL: idpMetadataURL,
// 		URL:            *rootURL,
// 		Key:            keyPair.PrivateKey.(*rsa.PrivateKey),
// 		Certificate:    keyPair.Leaf,
// 	})
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	return saml.NewSAMLSecurity(samlSP, conf), samlSP, nil
// }

// NewSecurityFromConfig sets up a full security chain from a a given service configuration.
func NewSecurityFromConfig(cfg *config.ServiceConfig) (chain.SecurityChain, CleanupFn, error) {
	security, err := NewConfiguredSecurityFromConfig(cfg)
	if err != nil {
		return nil, func() {}, err
	}
	return security.Chain, security.Cleanup, nil
}

// NewConfiguredSecurityFromConfig sets up a full security from a given service configuration.
func NewConfiguredSecurityFromConfig(cfg *config.ServiceConfig) (*ConfiguredSecurity, error) {
	configuredSecurity := &ConfiguredSecurity{}
	securityChain := chain.NewSecurityChain()

	configuredSecurity.Chain = securityChain

	if cfg.Disable {
		log.Println("WARN: Security is disabled. Please check your configuration.")
		return configuredSecurity, nil
	}

	if cfg.IgnorePatterns != nil {
		for _, pattern := range cfg.IgnorePatterns {
			if err := securityChain.AddIgnorePattern(pattern); err != nil {
				return nil, err
			}
		}
	}

	if cfg.IgnoreHTTPMethods != nil {
		for _, method := range cfg.IgnoreHTTPMethods {
			securityChain.IgnoreHTTPMethod(method)
		}
	} else {
		securityChain.IgnoreHTTPMethod("OPTIONS")
	}

	managerCleanup := func() {}
	samlCleanup := func() {}

	cleanup := func() {
		managerCleanup()
		samlCleanup()
	}

	if cfg.SecurityConfig.KeysDir != "" {
		keyStore, err := tools.NewDirKeyStore(cfg.SecurityConfig.KeysDir)
		if err != nil {
			return nil, err
		}
		configuredSecurity.KeyStore = keyStore
	}

	if cfg.SecurityConfig.JWTConfig != nil {
		// jwtSpec := &goa.JWTSecurity{
		// 	Name:        "Authorization",
		// 	Description: cfg.JWTConfig.Description,
		// 	In:          goa.LocHeader,
		// 	Scopes: map[string]string{
		// 		"api:read":  "Read API resource",
		// 		"api:write": "Write API resource",
		// 	},
		// }
		pk, err := configuredSecurity.KeyStore.GetPublicKey()
		if err != nil {
			return nil, err
		}
		jwtMiddleware, err := jwt.NewJWTMiddleware(pk.(string))
		if err != nil {
			return nil, err
		}
		securityChain.AddMiddleware(jwtMiddleware)
	}

	// if cfg.SecurityConfig.OAuth2Config != nil {
	// 	oauth2Spec := &goa.OAuth2Security{
	// 		AuthorizationURL: cfg.OAuth2Config.AuthorizationURL,
	// 		TokenURL:         cfg.OAuth2Config.TokenURL,
	// 		Flow:             "accessCode",
	// 		Description:      cfg.OAuth2Config.Description,
	// 		Scopes: map[string]string{
	// 			"api:read":  "Read API resource",
	// 			"api:write": "Write API resource",
	// 		},
	// 	}

	// 	oauth2Middleware := oauth2.NewOAuth2Security(cfg.SecurityConfig.KeysDir, oauth2Spec)
	// 	securityChain.AddMiddleware(oauth2Middleware)
	// }

	// if cfg.SecurityConfig.SAMLConfig != nil {
	// 	samlMiddleware, spMiddleware, err := newSAMLSecurity(cfg.GatewayURL, cfg.SAMLConfig)
	// 	if err != nil {
	// 		return nil, err
	// 	}

	// 	sc, err := saml.RegisterSP(spMiddleware, cfg.SAMLConfig)
	// 	if err != nil {
	// 		return nil, err
	// 	}
	// 	samlCleanup = sc

	// 	securityChain.AddMiddleware(samlMiddleware)
	// }

	// if cfg.SecurityConfig.JWTConfig == nil &&
	// 	cfg.SecurityConfig.OAuth2Config == nil &&
	// 	cfg.SecurityConfig.SAMLConfig == nil {
	// 	// No security defined
	// 	return configuredSecurity, nil

	// }

	// securityChain.AddMiddleware(chain.CheckAuth)

	if cfg.ACLConfig != nil && !cfg.ACLConfig.Disable {
		manager, mc, err := acl.NewBackendLadonManager(&cfg.DBConfig)
		if err != nil {
			return nil, err
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
			return nil, err
		}

		// if cfg.ACLConfig.Policies != nil {
		// 	for _, policy := range cfg.ACLConfig.Policies {
		// 		ladonPolicy := &ladon.DefaultPolicy{
		// 			ID:          policy.ID,
		// 			Actions:     policy.Actions,
		// 			Description: policy.Description,
		// 			Effect:      policy.Effect,
		// 			Resources:   policy.Resources,
		// 			Subjects:    policy.Subjects,
		// 		}
		// 		if policy.Conditions != nil {
		// 			conditions, e := conditionsFromConfig(policy.Conditions)
		// 			if e != nil {
		// 				return nil, e
		// 			}
		// 			ladonPolicy.Conditions = conditions
		// 		}
		// 		e := addOrUpdatePolicy(ladonPolicy, manager)
		// 		if e != nil {
		// 			return nil, e
		// 		}
		// 	}
		// }

		// aclMiddleware, err := acl.NewACLMiddleware(manager)
		// if err != nil {
		// 	return nil, err
		// }
		// securityChain.AddMiddleware(aclMiddleware)
		configuredSecurity.ACLManager = manager
	}

	configuredSecurity.Cleanup = cleanup

	return configuredSecurity, nil
}

func addOrUpdatePolicy(policy ladon.Policy, manager *acl.BackendLadonManager) error {
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
