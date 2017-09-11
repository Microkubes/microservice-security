package saml

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/JormungandrK/microservice-security/auth"
	"github.com/JormungandrK/microservice-security/chain"
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
				return goa.ErrNotFound("SAML Metadata route not defined")
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
				RedirectUser(spMiddleware, rw, req)
				return goa.ErrUnauthorized(fmt.Sprintf("missing cookie %s", CookieName))
			}

			tokenClaims := TokenClaims{}
			token, err := jwt.ParseWithClaims(cookie.Value, &tokenClaims, func(t *jwt.Token) (interface{}, error) {
				secretBlock := x509.MarshalPKCS1PrivateKey(spMiddleware.ServiceProvider.Key)
				return secretBlock, nil
			})

			if err != nil || !token.Valid {
				RedirectUser(spMiddleware, rw, req)
				return goa.ErrUnauthorized(fmt.Sprintf("invalid SAML token: %s", err))
			}

			if err := tokenClaims.StandardClaims.Valid(); err != nil {
				RedirectUser(spMiddleware, rw, req)
				return goa.ErrUnauthorized("invalid SAML token standard claims: %s", err)
			}

			// Audience basically identifies the audience [Service providers]. Audience is the EntityID of SP.
			if tokenClaims.Audience != spMiddleware.ServiceProvider.Metadata().EntityID {
				RedirectUser(spMiddleware, rw, req)
				return goa.ErrUnauthorized("invalid audience from SAML token")
			}

			attributes := tokenClaims.Attributes

			if _, ok := attributes["username"]; !ok {
				return jwt.NewValidationError("Username is missing form SAML token", jwt.ValidationErrorClaimsInvalid)
			}
			username := attributes["username"][0]

			if _, ok := attributes["userId"]; !ok {
				return jwt.NewValidationError("User ID is missing form SAML token", jwt.ValidationErrorClaimsInvalid)
			}
			userID := attributes["userId"][0]

			if reflect.TypeOf(username).String() != "string" {
				return jwt.NewValidationError("invalid username from SAML token", jwt.ValidationErrorClaimsInvalid)
			}

			if reflect.TypeOf(userID).String() != "string" {
				return jwt.NewValidationError("invalid user ID from SAML token", jwt.ValidationErrorClaimsInvalid)
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

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := saml.RandReader.Read(rv); err != nil {
		panic(err)
	}
	return rv
}

// Redirect user
func RedirectUser(spMiddleware *samlsp.Middleware, rw http.ResponseWriter, req *http.Request) {
	// if req.URL.Path == spMiddleware.ServiceProvider.AcsURL.Path {
	// 	panic("don't wrap Middleware with RequireAccount")
	// }

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
