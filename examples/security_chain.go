package examples

// import (
// 	"fmt"
// 	"net/http"
// 	"net/http/httptest"
// 	"net/url"
// 	"strings"

// 	"context"

// 	"github.com/Microkubes/microservice-security/auth"
// 	"github.com/Microkubes/microservice-security/chain"
// 	"github.com/keitaroinc/goa"
// )

// // NoAuthenticationPresent is a custom error for the auth middleware generated
// // when there is no authentication created
// var NoAuthenticationPresent = goa.NewErrorClass("authentication_required", 401)

// // DBUser represents a user stored in some persistence.
// type DBUser struct {
// 	ID            string
// 	Username      string
// 	Roles         []string
// 	Organizations []string
// }

// // UserRepository is an in-memory user data store. It is a map holding the users.
// // The key is composed of the username and password: <username>:<password>.
// type UserRepository map[string]*DBUser

// // FindByUsernameAndPassword looks up a user by its username and password in the UserRepository.
// func (repo UserRepository) FindByUsernameAndPassword(username string, pass string) *DBUser {
// 	key := fmt.Sprintf("%s:%s", username, pass)
// 	user := repo[key]
// 	return user
// }

// // CheckAuthInContextMiddleware is a chain.SecurityChainMiddleware that performs a check for the Auth object in the context.
// // This middleware ilustrates the usage of the auth package (auth.HasAuth function).
// // Note that the middleware returns an Goa error (custom defined for the purposes of the auth chain).
// // Later on, when the chain will return control over to Goa, this error will be serialized and retuned back to the client.
// // Returnning an error would cause the chain to break after this middleware and would return to Goa immediately. Since
// // the chain itself would return an error, this would also break the Goa chain and the actual microservice action will not
// // be called.
// func CheckAuthInContextMiddleware(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
// 	if !auth.HasAuth(ctx) {
// 		return ctx, rw, NoAuthenticationPresent("No authentication present in request")
// 	}
// 	return ctx, rw, nil
// }

// // DummyUserPassAuthBuilder returns a chain.MiddlewareBuilder factory function.
// // This illustrates passing a custom data to a chain.MiddlewareBuilder. In this
// // case we're sending a UserRepository that is used by the middleware to check
// // the username+password, but in real-world scenario we can pass a secret key or
// // a security store path to the middleware.
// func DummyUserPassAuthBuilder(userRepo UserRepository) chain.MiddlewareBuilder {
// 	// this is the actual chain.MiddlewareBuilder function.
// 	return func() chain.SecurityChainMiddleware {
// 		// chain.MiddlewareBuilder returns a chain.SecurityChainMiddleware that performs
// 		// the actual check and populates the context with auth.Auth object.
// 		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
// 			username := req.FormValue("username")
// 			password := req.FormValue("password")

// 			if username != "" && password != "" {
// 				username = strings.TrimSpace(username)
// 				password = strings.TrimSpace(password)

// 				// we're using the UserRepository from the closure, passed to the builder.
// 				user := userRepo.FindByUsernameAndPassword(username, password)

// 				if user != nil {
// 					// If there is a user with the user+pass, we map the DBUser to an auth.Auth object.
// 					authentication := &auth.Auth{
// 						Username:      user.Username,
// 						UserID:        user.ID,
// 						Roles:         user.Roles,
// 						Organizations: user.Organizations,
// 					}

// 					// we're returning the new context with Auth set.
// 					return auth.SetAuth(ctx, authentication), rw, nil
// 				}

// 			}
// 			// If we didn't find a user, we're returning the empty context.
// 			return ctx, rw, nil
// 		}
// 	}
// }

// func init() {
// 	// set up fake user repository
// 	userRepo := make(UserRepository)
// 	userRepo["testuser:testpass"] = &DBUser{
// 		ID:            "631b3b42-26aa-483e-81e7-66a9d6ffca29",
// 		Username:      "testuser",
// 		Roles:         []string{"user"},
// 		Organizations: []string{"Jormungandr"},
// 	}

// 	// register the security middleware type
// 	// this registers a MiddlewareBuilder for a security type "dummy".
// 	// note that we're enclosing userRepo hereby passing it to the builder function.
// 	chain.NewSecuirty("dummy", DummyUserPassAuthBuilder(userRepo))
// }

// // SecurityChainExample illustrates setting up a security chain with 2 middlewares:
// // 1. the "dummy" middleware that should create the Auth
// // 2. Middleware that checks for Auth object in the context.
// func SecurityChainExample() {

// 	// Create the security chain
// 	securityChain := chain.NewSecurityChain()
// 	securityChain.AddMiddlewareType("dummy")
// 	securityChain.AddMiddleware(CheckAuthInContextMiddleware)

// 	// we're executing the security chain with fake HTTP request with valid credentials.
// 	_, _, _, err := securityChain.Execute(context.Background(), nil, generateFakeRequest("testuser", "testpass"))

// 	if err != nil {
// 		panic(err)
// 	}
// }

// // SecurityChainExampleFailAuth illustrates setting up a security chain same as SecurityChainExample,
// // but the request contains wrong authentication and the chain returns an error.
// func SecurityChainExampleFailAuth() {
// 	// Create the security chain
// 	securityChain := chain.NewSecurityChain()
// 	securityChain.AddMiddlewareType("dummy")
// 	securityChain.AddMiddleware(CheckAuthInContextMiddleware)

// 	// we're executing the security chain with fake HTTP request, but with invalid credentials.
// 	_, _, _, err := securityChain.Execute(context.Background(), nil, generateFakeRequest("user", "incorrect"))

// 	if err == nil {
// 		panic("Auth should not pass")
// 	}

// 	fmt.Println("Chain exited with error (as expected): ", err.Error())
// }

// func generateFakeRequest(username string, pass string) *http.Request {

// 	req := httptest.NewRequest("POST", "http://example.com", nil)

// 	form := url.Values{}
// 	form.Add("username", username)
// 	form.Add("password", pass)

// 	req.PostForm = form

// 	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

// 	return req
// }
