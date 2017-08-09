package auth

import (
	"testing"

	"context"
)

func TestGetAuth(t *testing.T) {
	ctx := context.Background()
	auth := &Auth{}

	sc := &SecurityContext{
		Auth: auth,
	}

	ctx = context.WithValue(ctx, SecurityContextKey, sc)

	authInContext := GetAuth(ctx)

	if authInContext == nil {
		panic("Auth object was expected")
	}

	if authInContext != auth {
		panic("Expected to have the pointer to the same Auth object")
	}
}

func TestHasContext_Yes(t *testing.T) {
	ctx := context.Background()
	auth := &Auth{}

	sc := &SecurityContext{
		Auth: auth,
	}

	ctx = context.WithValue(ctx, SecurityContextKey, sc)

	hasAuth := HasAuth(ctx)

	if !hasAuth {
		panic("Expected to have Auth object in context")
	}
}

func TestHasContext_Nope(t *testing.T) {
	ctx := context.Background()

	hasAuth := HasAuth(ctx)

	if hasAuth {
		panic("Expected NOT to have Auth object in context")
	}
}

func TestSetAuth(t *testing.T) {
	ctx := context.Background()
	auth := &Auth{}

	ctx = SetAuth(ctx, auth)

	sc := ctx.Value(SecurityContextKey).(*SecurityContext)

	if sc == nil {
		panic("Expected SecurityContext to be set in context.")
	}
	if sc.Auth == nil {
		panic("Expected to have Auth in SecurityContext")
	}
	if sc.Auth != auth {
		panic("Expected to set the pointer to the same auth object.")
	}
}

func TestClearContext(t *testing.T) {
	ctx := context.Background()
	sc := &SecurityContext{}

	ctx = context.WithValue(ctx, SecurityContextKey, sc)

	ctx = ClearSecurityContext(ctx)

	scInContext := ctx.Value(SecurityContextKey)

	if scInContext != nil {
		panic("Expected NOT to find the auth object in context")
	}
}
