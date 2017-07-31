package chain

import (
	"fmt"
	"net/http"

	"context"
)

type SecurityChainMiddleware func(context.Context, http.ResponseWriter, *http.Request) (context.Context, http.ResponseWriter, error)

type MiddlewareBuilder func() SecurityChainMiddleware

type SecurityChain interface {
	AddMiddleware(middleware SecurityChainMiddleware) SecurityChain

	AddMiddlewareType(middlewareType string) (SecurityChain, error)

	Execute(ctx context.Context, rw http.ResponseWriter, req *http.Request) error
}

type Chain struct {
	MiddlewareList []SecurityChainMiddleware
}

func (chain *Chain) AddMiddleware(middleware SecurityChainMiddleware) SecurityChain {
	chain.MiddlewareList = append(chain.MiddlewareList, middleware)
	return chain
}

func (chain *Chain) AddMiddlewareType(middlewareType string) (SecurityChain, error) {
	middleware, err := buildSecurityMiddleware(middlewareType)
	if err != nil {
		return nil, err
	}
	return chain.AddMiddleware(middleware), nil
}

func (chain *Chain) Execute(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
	var err error
	for _, middleware := range chain.MiddlewareList {
		ctx, rw, err = middleware(ctx, rw, req)
		if err != nil {
			return err
		}
	}
	return nil
}

type SecurityMiddlewareBuilders map[string]MiddlewareBuilder

var securityMiddlwareRegistar = make(SecurityMiddlewareBuilders)

func NewSecuirty(mechanismType string, builder MiddlewareBuilder) error {
	_, ok := securityMiddlwareRegistar[mechanismType]
	if ok {
		return fmt.Errorf("Already registered security mechanism: %s", mechanismType)
	}
	securityMiddlwareRegistar[mechanismType] = builder
	return nil
}

func GetSecurityBuilder(mechanismType string) (MiddlewareBuilder, error) {
	builder, ok := securityMiddlwareRegistar[mechanismType]
	var err error
	if !ok {
		err = fmt.Errorf("No security builder found for %s", mechanismType)
	}
	return builder, err
}

func buildSecurityMiddleware(mechanismType string) (SecurityChainMiddleware, error) {
	builder, err := GetSecurityBuilder(mechanismType)
	if err != nil {
		return nil, err
	}
	return builder(), nil
}
