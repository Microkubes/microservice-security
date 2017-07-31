package auth

import (
	"testing"

	"context"
)

func TestGetAuth(t *testing.T) {
	ctx := context.Background()
	auth := &Auth{}
	ctx = context.WithValue(ctx, ContextAuthKey, auth)

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
	ctx = context.WithValue(ctx, ContextAuthKey, auth)

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

	authInContext := ctx.Value(ContextAuthKey)

	if authInContext == nil {
		panic("Expected the auth to be set in context.")
	}

	if authInContext != auth {
		panic("Expected to set the pointer to the same auth object.")
	}
}

func TestClearAuth(t *testing.T) {
	ctx := context.Background()
	auth := &Auth{}

	ctx = context.WithValue(ctx, ContextAuthKey, auth)

	ctx = ClearAuth(ctx)

	authInContext := ctx.Value(ContextAuthKey)

	if authInContext != nil {
		panic("Expected NOT to find the auth object in context")
	}
}
