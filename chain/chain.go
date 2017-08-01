package chain

import (
	"fmt"
	"net/http"

	"context"
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

// MiddlewareBuilder is a builder/factory for a particular SecurityChainMiddleware.
// Returns a function of type SecurityChainMiddleware.
type MiddlewareBuilder func() SecurityChainMiddleware

// SecurityChain represents the full security chain and exposes functions for
// adding SecurityChainMiddleware to the chain.
// It also exposes a function for executing the chain.
type SecurityChain interface {

	// AddMiddleware adds new SecurityChainMiddleware to the end of the security chain.
	AddMiddleware(middleware SecurityChainMiddleware) SecurityChain

	// AddMiddlewareType adds a middleware to the end of the chain. The acutal SecurityChainMiddleware
	// is build by calling the MiddlewareBuilder for the specific registered type of middleware.
	// See NewSecuirty function for retgistering MiddlewareBuilder for a specific security middleware.
	AddMiddlewareType(middlewareType string) (SecurityChain, error)

	// Execute executes the security chain.
	// It takes context.Context htto.ResponseWriter and a pointer to http.Request as arguments.
	// After executing all SecurityChainMiddleware in the chain, it returns the resulting context.Context,
	// http.ResponseWriter and *http.Request. This may be different from the parameters passed to the function.
	// If an error occured during executing the chain, and error is returned.
	Execute(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, *http.Request, error)
}

// Chain represents a SecurityChain and holds a list of all SecurityChainMiddleware in the order as they are added.
type Chain struct {
	MiddlewareList []SecurityChainMiddleware
}

// AddMiddleware appends a SecurityChainMiddleware to the end of middleware list in the chain.
func (chain *Chain) AddMiddleware(middleware SecurityChainMiddleware) SecurityChain {
	chain.MiddlewareList = append(chain.MiddlewareList, middleware)
	return chain
}

// AddMiddlewareType appends a SecurityChainMiddleware to the end of the middleware in the chain.
// The SecurityChainMiddleware is build using MiddlewareBuilder factory.
// If there is no MiddlewareBuilder registered for the specific type or an error occurs
// while calling the builder, an error is returned.
func (chain *Chain) AddMiddlewareType(middlewareType string) (SecurityChain, error) {
	middleware, err := buildSecurityMiddleware(middlewareType)
	if err != nil {
		return nil, err
	}
	return chain.AddMiddleware(middleware), nil
}

// Execute executes the security chain by calling all SecurityChainMiddleware in the middleware list in the
// order as they are added.
func (chain *Chain) Execute(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, *http.Request, error) {
	var err error
	for _, middleware := range chain.MiddlewareList {
		ctx, rw, err = middleware(ctx, rw, req)
		if err != nil {
			return ctx, rw, req, err
		}
	}
	return ctx, rw, req, nil
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
	var middlewareList []SecurityChainMiddleware
	return &Chain{
		MiddlewareList: middlewareList,
	}
}
