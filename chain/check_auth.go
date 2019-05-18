package chain

import (
	"net/http"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/keitaroinc/goa"

	"context"
)

// ErrAuthRequired is a an error builder for HTTP Authentication Required class of errors.
var ErrAuthRequired = goa.NewErrorClass("authentication-required", 401)

// CheckAuth is a basic chain.SecurityChainMiddleware that checks if an auth.Auth object is set in context.
func CheckAuth(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
	if !auth.HasAuth(ctx) {
		return ctx, rw, ErrAuthRequired("Authentication Required")
	}
	return ctx, rw, nil
}
