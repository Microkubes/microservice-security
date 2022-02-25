package chain

import (
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"context"

	"github.com/labstack/echo/v4"
)

// SecurityChainMiddleware is the basic constituent of the security chain. It acts as filter
// processing the incoming Request. Each request is passed to a SecurityChainMiddleware
// along with a context and ResponseWriter. After processing, the SecurityChainMiddleware
// should return the context and the ResponseWriter which will be passed to the next
// SecurityChainMiddleware in the security chain. This gives an option of modifying the
// context by adding some information in it (usually Auth) and optinally modifying the
// ResponseWriter itself.
// The SecurityChainMiddleware must return non-nil values for the context and the ResponseWriter.
// If an error is returned, the security chain terminates - no other middleware handlers are
// going to be called next.
type SecurityChainMiddleware func(context.Context, http.ResponseWriter, *http.Request) (context.Context, http.ResponseWriter, error)

// EchoMiddleware represents a single middleware function that will be part of a security chain.
type EchoMiddleware func(next echo.HandlerFunc) echo.HandlerFunc

// MiddlewareBuilder is a builder/factory for a particular SecurityChainMiddleware.
// Returns a function of type SecurityChainMiddleware.
type MiddlewareBuilder func() SecurityChainMiddleware

// SecurityChain represents the full security chain and exposes functions for
// adding SecurityChainMiddleware to the chain.
// It also exposes a function for executing the chain.
type SecurityChain interface {

	// AddMiddleware adds new SecurityChainMiddleware to the end of the security chain.
	AddMiddleware(middleware EchoMiddleware) SecurityChain

	// AddMiddlewareType adds a middleware to the end of the chain. The actual SecurityChainMiddleware
	// is build by calling the MiddlewareBuilder for the specific registered type of middleware.
	// See NewSecurity function for registering MiddlewareBuilder for a specific security middleware.
	// AddMiddlewareType(middlewareType string) (SecurityChain, error)

	// Execute executes the security chain.
	// It takes context.Context http.ResponseWriter and a pointer to http.Request as arguments.
	// After executing all SecurityChainMiddleware in the chain, it returns the resulting context.Context,
	// http.ResponseWriter and *http.Request. This may be different from the parameters passed to the function.
	// If an error occurred during executing the chain, and error is returned.
	Execute(e *echo.Echo) *echo.Echo

	// AddIgnorePattern adds a pattern for the request path that will be ignored by this chain.
	// The request path will be matched against the ignore patterns and if match is found, then
	// the chain will not be executed and the request processing will be passed through.
	// This is useful for public resources for which we don't check the auth.
	// If the pattern is invalid, an error will be returned and the pattern is not added to the
	// list of ignore patterns.
	AddIgnorePattern(pattern string) error

	// IgnoreHTTPMethod add an HTTP method that will be ignored. Every HTTP request with this method (verb) shall
	// be passed through and ignored by the security chain.
	IgnoreHTTPMethod(method string)
}

// Chain represents a SecurityChain and holds a list of all SecurityChainMiddleware in the order as they are added.
type Chain struct {
	MiddlewareFuncs    []EchoMiddleware
	IgnorePatterns     []*regexp.Regexp
	IgnoredHTTPMethods []string
}

// AddMiddleware appends a SecurityChainMiddleware to the end of middleware list in the chain.
func (c *Chain) AddMiddleware(middleware EchoMiddleware) SecurityChain {
	c.MiddlewareFuncs = append(c.MiddlewareFuncs, middleware)
	return c
}

// AddMiddlewareType appends a SecurityChainMiddleware to the end of the middleware in the chain.
// The SecurityChainMiddleware is build using MiddlewareBuilder factory.
// If there is no MiddlewareBuilder registered for the specific type or an error occurs
// while calling the builder, an error is returned.
// func (chain *Chain) AddMiddlewareType(middlewareType string) (SecurityChain, error) {
// 	middleware, err := buildSecurityMiddleware(middlewareType)
// 	if err != nil {
// 		return nil, err
// 	}
// 	return chain.AddMiddleware(middleware), nil
// }

// Execute executes the security chain by calling all SecurityChainMiddleware in the middleware list in the
// order as they are added.
func (c *Chain) Execute(e *echo.Echo) *echo.Echo {
	// if !chain.preflightCheck(req) {
	// 	return ctx, rw, req, nil
	// }
	// var err error
	// for _, middleware := range chain.MiddlewareList {
	// 	ctx, rw, err = middleware(ctx, rw, req)
	// 	if err != nil {
	// 		return ctx, rw, req, err
	// 	}
	// }
	// return ctx, rw, req, nil
	for _, m := range c.MiddlewareFuncs {
		log.Println("Im now executing ", m, " as part of the middleware chain")
		e.Use(echo.MiddlewareFunc(m))
	}
	return e
}

func (chain *Chain) isRequestIgnoredPattern(req *http.Request) bool {
	if chain.IgnorePatterns == nil {
		return false
	}
	path := req.URL.Path
	for _, pattern := range chain.IgnorePatterns {
		if pattern.MatchString(path) {
			return true
		}
	}
	return false
}

// AddIgnorePattern adds an ignore pattern to this security chain.
// The pattern is compiled to a regular expression and must be valid
// regular expression. If the pattern is not valid, an error will be
// returned and the pattern is not added to the list of ignore patterns.
func (chain *Chain) AddIgnorePattern(pattern string) error {
	reg, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	chain.IgnorePatterns = append(chain.IgnorePatterns, reg)
	return nil
}

func (chain *Chain) preflightCheck(req *http.Request) bool {
	// check HTTP request method
	if !chain.checkHTTPMethod(req.Method) {
		return false
	}
	if chain.isRequestIgnoredPattern(req) {
		return false
	}
	return true
}

func (chain *Chain) checkHTTPMethod(method string) bool {
	if chain.IgnoredHTTPMethods == nil {
		return true
	}
	for _, ignoredMethod := range chain.IgnoredHTTPMethods {
		if ignoredMethod == method {
			return false
		}
	}
	return true
}

// IgnoreHTTPMethod add an HTTP method to be ignored by the security chain.
func (chain *Chain) IgnoreHTTPMethod(method string) {
	method = strings.ToUpper(method)
	chain.IgnoredHTTPMethods = append(chain.IgnoredHTTPMethods, method)
}

// SecurityMiddlewareBuilders is a map that maps a security type to a specific MiddlewareBuilder.
type SecurityMiddlewareBuilders map[string]MiddlewareBuilder

// securityMiddlwareRegistar is the actual register of SecurityMiddlewareBuilders.
var securityMiddlwareRegistar = make(SecurityMiddlewareBuilders)

// NewSecuirty registers a MiddlewareBuilder for a specific security mechanism type (ex "JWT" "OAuth2", "SAML").
func NewSecuirty(mechanismType string, builder MiddlewareBuilder) error {
	_, ok := securityMiddlwareRegistar[mechanismType]
	if ok {
		return fmt.Errorf("Already registered security mechanism: %s", mechanismType)
	}
	securityMiddlwareRegistar[mechanismType] = builder
	return nil
}

// GetSecurityBuilder returns a MiddlewareBuilder for the security mechanism from the global registry.
// If no builder exists for that type of security, an error is returned.
func GetSecurityBuilder(mechanismType string) (MiddlewareBuilder, error) {
	builder, ok := securityMiddlwareRegistar[mechanismType]
	var err error
	if !ok {
		err = fmt.Errorf("No security builder found for %s", mechanismType)
	}
	return builder, err
}

// buildSecurityMiddleware builds new SecurityChainMiddleware for the specified security type.
// If no MiddlewareBuilder is found for the security type, an error is returned.
func buildSecurityMiddleware(mechanismType string) (SecurityChainMiddleware, error) {
	builder, err := GetSecurityBuilder(mechanismType)
	if err != nil {
		return nil, err
	}
	return builder(), nil
}

// NewSecurityChain creates a new SecurityChain.
func NewSecurityChain() SecurityChain {
	var middlewareList []EchoMiddleware
	return &Chain{
		MiddlewareFuncs:    middlewareList,
		IgnorePatterns:     []*regexp.Regexp{},
		IgnoredHTTPMethods: []string{},
	}
}

// AsSecurityMiddleware wraps a SecurityChain into a SecurityChainMiddleware which later
// can be used as part of another SecurityChain.
// func AsSecurityMiddleware(chain SecurityChain) EchoMiddleware {
// 	// return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
// 	// 	c, rw, _, err := chain.Execute(ctx, rw, req)
// 	// 	return c, rw, err
// 	// }
// 	return func(next echo.HandlerFunc) echo.HandlerFunc {
// 		return chain.Execute()
// 	}
// }
