package saml

import (
	"bytes"
	"context"
	// "crypto/tls"

	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-security/chain"
	"github.com/Microkubes/microservice-tools/config"
	"github.com/afex/hystrix-go/hystrix"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/dgrijalva/jwt-go"
	"github.com/keitaroinc/goa"
)

const (
	// SAMLSecurityType is the name of the security type (JWT, OAUTH2, SAML...)
	SAMLSecurityType = "SAML"
	// CookieName name for saml token
	CookieName = "token"
)

var jwtSigningMethod = jwt.SigningMethodHS256

// TokenClaims SAML claims
type TokenClaims struct {
	jwt.StandardClaims
	Attributes map[string][]string `json:"attr"`
}

// UserPayload is the user payload
type UserPayload struct {
	// Status of user account
	Active bool `form:"active" json:"active" xml:"active"`
	// Email of user
	Email string `form:"email" json:"email" xml:"email"`
	// External id of user
	ExternalID string `form:"externalId,omitempty" json:"externalId,omitempty" xml:"externalId,omitempty"`
	// Full name of user
	Fullname string `form:"fullname" json:"fullname" xml:"fullname"`
	// Roles of user
	Roles []string `form:"roles" json:"roles" xml:"roles"`
}

// EmailPayload holds the email payload
type EmailPayload struct {
	// Email of the user
	Email string
}

// NewSAMLSecurity creates a SAML SecurityChainMiddleware using RSA private key.
func NewSAMLSecurity(spMiddleware *samlsp.Middleware, samlConf *config.SAMLConfig) chain.SecurityChainMiddleware {
	goaMiddleware := NewSAMLSecurityMiddleware(spMiddleware, samlConf)
	return chain.ToSecurityChainMiddleware(SAMLSecurityType, goaMiddleware)
}

// NewSAMLSecurityMiddleware creates a middleware that checks for the presence of a cookie and validates its content.
// It also serve SP metadata on /saml/metadata route and SAML Assertion Consumer Service on /saml/acs route.
func NewSAMLSecurityMiddleware(spMiddleware *samlsp.Middleware, samlConfig *config.SAMLConfig) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			// Serve /saml/acs
			if req.URL.Path == spMiddleware.ServiceProvider.AcsURL.Path {
				req.ParseForm()
				assertion, err := spMiddleware.ServiceProvider.ParseResponse(req, getPossibleRequestIDs(spMiddleware, req))
				if err != nil {
					if parseErr, ok := err.(*saml.InvalidResponseError); ok {
						spMiddleware.ServiceProvider.Logger.Printf("RESPONSE: ===\n%s\n===\nNOW: %s\nERROR: %s",
							parseErr.Response, parseErr.Now, parseErr.PrivateErr)
					}
					http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
					return goa.ErrInvalidRequest("Cannot parse SAML Response")
				}

				spMiddleware.Authorize(rw, req, assertion)
				return chain.BreakChain("SAML ACS route not defined")
			}

			// Serve /saml/metadata
			if req.URL.Path == spMiddleware.ServiceProvider.MetadataURL.Path {
				buf, _ := xml.MarshalIndent(spMiddleware.ServiceProvider.Metadata(), "", "  ")
				rw.Header().Set("Content-Type", "application/samlmetadata+xml")
				rw.Write(buf)
				rw.WriteHeader(200)
				return chain.BreakChain("SAML Metadata route not defined")
			}

			cookie, err := req.Cookie(CookieName)
			if err != nil {
				return goa.ErrUnauthorized(fmt.Sprintf("missing cookie %s", CookieName))
			}

			tokenClaims := TokenClaims{}
			token, err := jwt.ParseWithClaims(cookie.Value, &tokenClaims, func(t *jwt.Token) (interface{}, error) {
				secretBlock := x509.MarshalPKCS1PrivateKey(spMiddleware.ServiceProvider.Key)
				return secretBlock, nil
			})

			if err != nil || !token.Valid {
				RedirectUser(spMiddleware, rw, req)
				return chain.BreakChain(fmt.Sprintf("invalid SAML token: %s", err))
			}

			if e := tokenClaims.StandardClaims.Valid(); e != nil {
				RedirectUser(spMiddleware, rw, req)
				return chain.BreakChain(fmt.Sprintf("invalid SAML token standard claims: %s", e))
			}

			// Audience basically identifies the audience [Service providers]. Audience is the EntityID of SP.
			if tokenClaims.Audience != spMiddleware.ServiceProvider.Metadata().EntityID {
				RedirectUser(spMiddleware, rw, req)
				return chain.BreakChain(
					fmt.Sprintf("invalid audience from SAML token, got %s, expected %s", tokenClaims.Audience, spMiddleware.ServiceProvider.Metadata().EntityID))
			}

			var email string
			var userID string
			attributes := tokenClaims.Attributes

			if attributes["email"] != nil && attributes["firstname"] != nil && attributes["lastname"] != nil {
				// User came from Google IdP.
				email = attributes["email"][0]
				firstName := attributes["firstname"][0]
				lastName := attributes["lastname"][0]

				user, _ := findUser(email, spMiddleware, samlConfig.UserServiceURL)

				if user == nil {
					user, err = registerUser(email, firstName, lastName, spMiddleware, samlConfig.RegistrationServiceURL)

					if err != nil {
						return err
					}
				}

				userID = user["id"].(string)

				for _, v := range user["roles"].([]interface{}) {
					attributes["roles"] = append(attributes["roles"], v.(string))
				}
				attributes["organizations"] = []string{}
				if organizations, ok := user["organizations"]; ok {
					if organizationsArr, ok := organizations.([]interface{}); ok {
						for _, org := range organizationsArr {
							attributes["organizations"] = append(attributes["organizations"], org.(string))
						}
					}
				}
				attributes["namespaces"] = []string{}
				if namespaces, ok := user["namespaces"]; ok {
					if namespacesArr, ok := namespaces.([]interface{}); ok {
						for _, ns := range namespacesArr {
							attributes["namespaces"] = append(attributes["namespaces"], ns.(string))
						}
					}
				}
			} else {
				// User came from custom IdP.
				if _, ok := attributes["eduPersonPrincipalName"]; !ok {
					return jwt.NewValidationError("Email is missing form SAML token", jwt.ValidationErrorClaimsInvalid)
				}
				email = attributes["eduPersonPrincipalName"][0]

				if _, ok := attributes["uid"]; !ok {
					return jwt.NewValidationError("User ID is missing form SAML token", jwt.ValidationErrorClaimsInvalid)
				}
				userID = attributes["uid"][0]

				if reflect.TypeOf(email).String() != "string" {
					return jwt.NewValidationError("invalid email from SAML token", jwt.ValidationErrorClaimsInvalid)
				}

				if reflect.TypeOf(userID).String() != "string" {
					return jwt.NewValidationError("invalid user ID from SAML token", jwt.ValidationErrorClaimsInvalid)
				}
			}

			namespaces, ok := attributes["namespaces"]
			if !ok {
				namespaces = []string{}
			}
			organizations, ok := attributes["organizatios"]
			if !ok {
				organizations = []string{}
			}
			authObj := &auth.Auth{
				Roles:         attributes["eduPersonAffiliation"],
				Organizations: organizations,
				Namespaces:    namespaces,
				Username:      email,
				UserID:        userID,
			}

			return h(auth.SetAuth(ctx, authObj), rw, req)
		}
	}
}

// getPossibleRequestIDs retrives the IDs of the SAML response
func getPossibleRequestIDs(spMiddleware *samlsp.Middleware, r *http.Request) []string {
	rv := []string{}
	for _, cookie := range r.Cookies() {
		if !strings.HasPrefix(cookie.Name, "saml_") {
			continue
		}
		spMiddleware.ServiceProvider.Logger.Printf("getPossibleRequestIDs: cookie: %s", cookie.String())

		jwtParser := jwt.Parser{
			ValidMethods: []string{jwtSigningMethod.Name},
		}
		token, err := jwtParser.Parse(cookie.Value, func(t *jwt.Token) (interface{}, error) {
			secretBlock := x509.MarshalPKCS1PrivateKey(spMiddleware.ServiceProvider.Key)
			return secretBlock, nil
		})
		if err != nil || !token.Valid {
			spMiddleware.ServiceProvider.Logger.Printf("... invalid token %s", err)
			continue
		}
		claims := token.Claims.(jwt.MapClaims)
		rv = append(rv, claims["id"].(string))
	}

	// If IDP initiated requests are allowed, then we can expect an empty response ID.
	if spMiddleware.AllowIDPInitiated {
		rv = append(rv, "")
	}

	return rv
}

// randomBytes generates n random bytes
func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

// RedirectUser redirects user to the IdP that is set in the metadata
func RedirectUser(spMiddleware *samlsp.Middleware, rw http.ResponseWriter, req *http.Request) {
	if req.URL.Path == spMiddleware.ServiceProvider.AcsURL.Path {
		panic("don't wrap Middleware with RequireAccount")
	}

	binding := saml.HTTPRedirectBinding
	bindingLocation := spMiddleware.ServiceProvider.GetSSOBindingLocation(binding)
	if bindingLocation == "" {
		binding = saml.HTTPPostBinding
		bindingLocation = spMiddleware.ServiceProvider.GetSSOBindingLocation(binding)
	}

	authRequest, err := spMiddleware.ServiceProvider.MakeAuthenticationRequest(bindingLocation)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
	}

	relayState := base64.URLEncoding.EncodeToString(randomBytes(42))

	secretBlock := x509.MarshalPKCS1PrivateKey(spMiddleware.ServiceProvider.Key)
	state := jwt.New(jwtSigningMethod)
	claims := state.Claims.(jwt.MapClaims)
	claims["id"] = authRequest.ID
	claims["uri"] = req.URL.String()
	signedState, err := state.SignedString(secretBlock)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	http.SetCookie(rw, &http.Cookie{
		Name:     fmt.Sprintf("saml_%s", relayState),
		Value:    signedState,
		MaxAge:   int(saml.MaxIssueDelay.Seconds()),
		HttpOnly: false,
		Path:     spMiddleware.ServiceProvider.AcsURL.Path,
	})

	if binding == saml.HTTPRedirectBinding {
		redirectURL := authRequest.Redirect(relayState)
		rw.Header().Add("Location", redirectURL.String())
		rw.WriteHeader(http.StatusFound)
		return
	}

	if binding == saml.HTTPPostBinding {
		rw.Header().Set("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-D8xB+y+rJ90RmLdP72xBqEEc0NUatn7yuCND0orkrgk='; "+
			"reflected-xss block; "+
			"referrer no-referrer;")
		rw.Header().Add("Content-type", "text/html")
		rw.Write([]byte(`<!DOCTYPE html><html><body>`))
		rw.Write(authRequest.Post(relayState))
		rw.Write([]byte(`</body></html>`))
		return
	}
}

// RegisterSP sends SP metadata to the SAML IdP
func RegisterSP(spMiddleware *samlsp.Middleware, conf *config.SAMLConfig) (func(), error) {
	payload, err := xml.MarshalIndent(spMiddleware.ServiceProvider.Metadata(), "", "  ")
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	output := make(chan *http.Response, 1)
	errorsChan := hystrix.Go("identity-provider-microservice.add-sp", func() error {
		resp, e := makeRequest(client, http.MethodPost, payload, fmt.Sprintf("%s/services", conf.IdentityProviderURL), spMiddleware)
		if e != nil {
			return e
		}
		output <- resp
		return nil
	}, nil)

	var addSPResp *http.Response
	select {
	case out := <-output:
		addSPResp = out
	case respErr := <-errorsChan:
		return nil, respErr
	}

	// Inspect status code from responses
	body, err := ioutil.ReadAll(addSPResp.Body)
	if err != nil {
		return nil, err
	}
	if addSPResp.StatusCode != 201 {
		err := errors.New(string(body))
		return nil, err
	}

	return func() {
		UnregisterSP(spMiddleware, conf)
	}, nil
}

// UnregisterSP deletes SP from SAML IdP
func UnregisterSP(spMiddleware *samlsp.Middleware, conf *config.SAMLConfig) {

	entityID := spMiddleware.ServiceProvider.Metadata().EntityID
	data := map[string]string{
		"serviceId": entityID,
	}

	payload, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}

	client := &http.Client{}
	output := make(chan *http.Response, 1)
	errorsChan := hystrix.Go("identity-provider-microservice.delete-sp", func() error {
		resp, e := makeRequest(client, http.MethodDelete, payload, fmt.Sprintf("%s/services", conf.IdentityProviderURL), spMiddleware)
		if e != nil {
			return e
		}
		output <- resp
		return nil
	}, nil)

	var deleteSPResp *http.Response
	select {
	case out := <-output:
		deleteSPResp = out
	case respErr := <-errorsChan:
		panic(respErr)
	}

	// Inspect status code from responses
	body, err := ioutil.ReadAll(deleteSPResp.Body)
	if err != nil {
		panic(err)
	}
	if deleteSPResp.StatusCode != 200 {
		err := errors.New(string(body))
		panic(err)
	}
}

// registerUser registers the user, it creates a user and profile
func registerUser(email string, firstName string, lastName string, spMiddleware *samlsp.Middleware, registrationServiceURL string) (map[string]interface{}, error) {
	hystrix.ConfigureCommand("register-microservice.register_user", hystrix.CommandConfig{
		Timeout:               10000,
		MaxConcurrentRequests: 1000,
		ErrorPercentThreshold: 25,
	})

	user := UserPayload{
		Fullname:   fmt.Sprintf("%s %s", firstName, lastName),
		Email:      email,
		ExternalID: fmt.Sprintf("google: %s", email),
		Roles:      []string{"user"},
		Active:     true,
	}

	payload, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	// tr := &http.Transport{
	// 	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	// }
	// client := &http.Client{Transport: tr}
	client := &http.Client{}
	output := make(chan *http.Response, 1)
	errorsChan := hystrix.Go("register-microservice.register_user", func() error {
		resp, e := makeRequest(client, http.MethodPost, payload, fmt.Sprintf("%s/register", registrationServiceURL), spMiddleware)
		if e != nil {
			return e
		}
		output <- resp
		return nil
	}, nil)

	var createUserResp *http.Response
	select {
	case out := <-output:
		createUserResp = out
	case respErr := <-errorsChan:
		return nil, respErr
	}

	// Inspect status code from response
	body, _ := ioutil.ReadAll(createUserResp.Body)
	if createUserResp.StatusCode != 201 {
		e := errors.New(string(body))
		return nil, e
	}

	var resp map[string]interface{}
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// findUser retrives the user by email
func findUser(email string, spMiddleware *samlsp.Middleware, userServiceURL string) (map[string]interface{}, error) {
	// config, err := config.LoadConfig("")
	// if err != nil {
	// 	panic(err)
	// }

	emailPayload := EmailPayload{
		Email: email,
	}

	payload, err := json.Marshal(emailPayload)
	if err != nil {
		return nil, err
	}

	client := &http.Client{}
	output := make(chan *http.Response, 1)
	errorsChan := hystrix.Go("user-microservice.find_by_email", func() error {
		resp, e := makeRequest(client, http.MethodPost, payload, fmt.Sprintf("%s/find/email", userServiceURL), spMiddleware)
		if e != nil {
			return e
		}
		output <- resp
		return nil
	}, nil)

	var createUserResp *http.Response
	select {
	case out := <-output:
		createUserResp = out
	case respErr := <-errorsChan:
		return nil, respErr
	}

	// Inspect status code from response
	body, _ := ioutil.ReadAll(createUserResp.Body)
	if createUserResp.StatusCode != 200 {
		e := errors.New(string(body))
		return nil, e
	}

	var resp map[string]interface{}
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// makeRequest makes http request
func makeRequest(client *http.Client, method string, payload []byte, url string, spMiddleware *samlsp.Middleware) (*http.Response, error) {
	req, err := http.NewRequest(method, url, bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}

	expire := time.Now().AddDate(0, 0, 1)
	tokenStr, err := generateSAMLToken(spMiddleware)
	if err != nil {
		return nil, err
	}
	cookie := http.Cookie{
		Name:       "token",
		Value:      tokenStr,
		Path:       "",
		Domain:     "",
		Expires:    expire,
		RawExpires: expire.Format(time.UnixDate),
		MaxAge:     86400,
		Secure:     true,
		HttpOnly:   true,
		Raw:        "",
		Unparsed:   []string{},
	}
	req.AddCookie(&cookie)

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, err
}

// generateSAMLToken generate signed SAML token
func generateSAMLToken(spMiddleware *samlsp.Middleware) (string, error) {
	encodedPrivatekKey := x509.MarshalPKCS1PrivateKey(spMiddleware.ServiceProvider.Key)
	claims := TokenClaims{}
	claims.Audience = spMiddleware.ServiceProvider.Metadata().EntityID
	claims.Attributes = map[string][]string{
		"userId":   []string{"system"},
		"username": []string{"system"},
		"roles":    []string{"system"},
	}
	tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := tokenHS.SignedString(encodedPrivatekKey)

	return tokenStr, err
}
