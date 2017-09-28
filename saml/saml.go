package saml

import (
	"context"
	"crypto/x509"
	// "crypto/tls"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"strings"

	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/chain"
	"github.com/JormungandrK/microservice-security/saml/config"
	"github.com/afex/hystrix-go/hystrix"
	"github.com/crewjam/saml"
	"github.com/crewjam/saml/samlsp"
	"github.com/dgrijalva/jwt-go"
	"github.com/goadesign/goa"
)

const (
	// SAMLSecurityType is the name of the security type (JWT, OAUTH2, SAML...)
	SAMLSecurityType = "SAML"
	// Cookie name for saml token
	CookieName = "token"
)

var jwtSigningMethod = jwt.SigningMethodHS256

// SAML claims
type TokenClaims struct {
	jwt.StandardClaims
	Attributes map[string][]string `json:"attr"`
}

// User payload
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
	// Name of user
	Username string `form:"username" json:"username" xml:"username"`
}

// Email payload
type EmailPayload struct {
	// Email of the user
	Email string
}

// NewSAMLSecurity creates a SAML SecurityChainMiddleware using RSA private key.
func NewSAMLSecurity(spMiddleware *samlsp.Middleware) chain.SecurityChainMiddleware {
	goaMiddleware := NewSAMLSecurityMiddleware(spMiddleware)
	return chain.ToSecurityChainMiddleware(SAMLSecurityType, goaMiddleware)
}

// NewSAMLSecurityMiddleware creates a middleware that checks for the presence of a cookie and validates its content.
// It also serve SP metadata on /saml/metadata route and SAML Assertion Consumer Service on /saml/acs route.
func NewSAMLSecurityMiddleware(spMiddleware *samlsp.Middleware) goa.Middleware {
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
				return goa.ErrNotFound("SAML ACS route not defined")
			}

			// Serve /saml/metadata
			if req.URL.Path == spMiddleware.ServiceProvider.MetadataURL.Path {
				buf, _ := xml.MarshalIndent(spMiddleware.ServiceProvider.Metadata(), "", "  ")
				rw.Header().Set("Content-Type", "application/samlmetadata+xml")
				rw.Write(buf)
				rw.WriteHeader(200)
				return chain.BreakChain("SAML Metadata route not defined")
			}

			// Code used to generate token for testing
			// sB := x509.MarshalPKCS1PrivateKey(spMiddleware.ServiceProvider.Key)
			// claims := TokenClaims{}
			// claims.Audience = "http://localhost:8082/saml/metadata"
			// claims.Attributes = map[string]interface{}{
			// 	"userId": "59b2e5120000000000000000",
			// 	"username": "test-user",
			// 	"roles": "user, admin",
			// 	"organizations": "Ozrg1, Org2",
			// }
			// tokenHS := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
			// tokenStr, err := tokenHS.SignedString(sB)
			// fmt.Println("===TOKEN===")
			// fmt.Println(tokenStr)
			// fmt.Println("===========")

			cookie, err := req.Cookie(CookieName)
			if err != nil {
				// RedirectUser(spMiddleware, rw, req)
				return goa.ErrUnauthorized(fmt.Sprintf("missing cookie %s", CookieName))
			}

			tokenClaims := TokenClaims{}
			token, err := jwt.ParseWithClaims(cookie.Value, &tokenClaims, func(t *jwt.Token) (interface{}, error) {
				secretBlock := x509.MarshalPKCS1PrivateKey(spMiddleware.ServiceProvider.Key)
				return secretBlock, nil
			})

			if err != nil || !token.Valid {
				return goa.ErrUnauthorized(fmt.Sprintf("invalid SAML token: %s", err))
			}

			if err := tokenClaims.StandardClaims.Valid(); err != nil {
				return goa.ErrUnauthorized("invalid SAML token standard claims: %s", err)
			}

			// Audience basically identifies the audience [Service providers]. Audience is the EntityID of SP.
			if tokenClaims.Audience != spMiddleware.ServiceProvider.Metadata().EntityID {
				return goa.ErrUnauthorized("invalid audience from SAML token")
			}

			var username string
			var userID string
			attributes := tokenClaims.Attributes

			if attributes["email"] != nil && attributes["firstname"] != nil && attributes["lastname"] != nil {
				// User came from Google IdP.
				email := attributes["email"][0]
				firstName := attributes["firstname"][0]
				lastName := attributes["lastname"][0]

				user, _ := findUser(email)

				if user == nil {
					user, err = registerUser(email, firstName, lastName)

					if err != nil {
						return err
					}
				}

				username = user["username"].(string)
				userID = user["id"].(string)

				for _, v := range user["roles"].([]interface{}) {
					attributes["roles"] = append(attributes["roles"], v.(string))
				}
			} else {
				// User came from custom IdP.
				if _, ok := attributes["username"]; !ok {
					return jwt.NewValidationError("Username is missing form SAML token", jwt.ValidationErrorClaimsInvalid)
				}
				username = attributes["username"][0]

				if _, ok := attributes["userId"]; !ok {
					return jwt.NewValidationError("User ID is missing form SAML token", jwt.ValidationErrorClaimsInvalid)
				}
				userID = attributes["userId"][0]

				if reflect.TypeOf(username).String() != "string" {
					return jwt.NewValidationError("invalid username from SAML token", jwt.ValidationErrorClaimsInvalid)
				}

				if reflect.TypeOf(userID).String() != "string" {
					return jwt.NewValidationError("invalid user ID from SAML token", jwt.ValidationErrorClaimsInvalid)
				}
			}

			authObj := &auth.Auth{
				Roles:         attributes["roles"],
				Organizations: attributes["organizations"],
				Username:      username,
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

// Generate n random bytes
func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

// Redirect user to the IdP the is set in the metadata
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

// Register the user, it creates a user and profile
func registerUser(email, firstName, lastName string) (map[string]interface{}, error) {
	config, err := config.LoadConfig("")
	if err != nil {
		panic(err)
	}

	hystrix.ConfigureCommand("register-microservice.register_user", hystrix.CommandConfig{
		Timeout:               10000,
		MaxConcurrentRequests: 1000,
		ErrorPercentThreshold: 25,
	})

	user := UserPayload{
		Fullname:   fmt.Sprintf("%s %s", firstName, lastName),
		Username:   email,
		Email:      email,
		ExternalID: fmt.Sprintf("google: %s", email),
		Roles:      []string{"user"},
		Active:     true,
	}

	payload, err := json.Marshal(user)
	if err != nil {
		return nil, err
	}

	//    tr := &http.Transport{
	//        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	//    }
	// client := &http.Client{Transport: tr}
	client := &http.Client{}
	output := make(chan *http.Response, 1)
	errorsChan := hystrix.Go("register-microservice.register_user", func() error {
		resp, err := postData(client, payload, fmt.Sprintf("%s/register", config.Services["microservice-registration"]))
		if err != nil {
			return err
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
		err := errors.New(string(body))
		return nil, err
	}

	var resp map[string]interface{}
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// Retrive the user by email
func findUser(email string) (map[string]interface{}, error) {
	config, err := config.LoadConfig("")
	if err != nil {
		panic(err)
	}

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
		resp, err := postData(client, payload, fmt.Sprintf("%s/find/email", config.Services["microservice-user"]))
		if err != nil {
			return err
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
		err := errors.New(string(body))
		return nil, err
	}

	var resp map[string]interface{}
	if err = json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}

	return resp, nil
}

// Make post request
func postData(client *http.Client, payload []byte, url string) (*http.Response, error) {
	resp, err := client.Post(fmt.Sprintf("%s", url), "application/json", bytes.NewBuffer(payload))
	return resp, err
}
