package auth

import (
	"fmt"
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
		t.Fatal("Auth object was expected")
	}

	if authInContext != auth {
		t.Fatal("Expected to have the pointer to the same Auth object")
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
		t.Fatal("Expected to have Auth object in context")
	}
}

func TestHasContext_Nope(t *testing.T) {
	ctx := context.Background()

	hasAuth := HasAuth(ctx)

	if hasAuth {
		t.Fatal("Expected NOT to have Auth object in context")
	}
}

func TestSetAuth(t *testing.T) {
	ctx := context.Background()
	auth := &Auth{}

	ctx = SetAuth(ctx, auth)

	sc := ctx.Value(SecurityContextKey).(*SecurityContext)

	if sc == nil {
		t.Fatal("Expected SecurityContext to be set in context.")
	}
	if sc.Auth == nil {
		t.Fatal("Expected to have Auth in SecurityContext")
	}
	if sc.Auth != auth {
		t.Fatal("Expected to set the pointer to the same auth object.")
	}
}

func TestClearContext(t *testing.T) {
	ctx := context.Background()
	sc := &SecurityContext{}

	ctx = context.WithValue(ctx, SecurityContextKey, sc)

	ctx = ClearSecurityContext(ctx)

	scInContext := ctx.Value(SecurityContextKey)

	if scInContext != nil {
		t.Fatal("Expected NOT to find the auth object in context")
	}
}

func TestGetSecurityContext(t *testing.T) {
	ctx := context.Background()
	sc := &SecurityContext{}

	ctx = context.WithValue(ctx, SecurityContextKey, sc)

	scInContext := GetSecurityContext(ctx)

	if scInContext == nil {
		t.Fatal("SecurityContext was expected")
	}
}

func TestGetSecurityErrors(t *testing.T) {
	ctx := context.Background()
	sc := &SecurityContext{}

	ctx = context.WithValue(ctx, SecurityContextKey, sc)

	sc.Errors = make(SecurityErrors)

	sc.Errors["JWT"] = fmt.Errorf("Some failure")

	errors := GetSecurityErrors(ctx)

	if errors == nil {
		t.Fatal("Expected to find security errors map")
	}

	if _, ok := (*errors)["JWT"]; !ok {
		t.Fatal("Expected to find JWT error in context.")
	}
}

func TestSetSecurityError(t *testing.T) {
	ctx := context.Background()

	ctx = SetSecurityError(ctx, "JWT", fmt.Errorf("JWT Error"))

	sc, ok := ctx.Value(SecurityContextKey).(*SecurityContext)
	if !ok {
		t.Fatal("Expected to find security context")
	}
	if _, ok := sc.Errors["JWT"]; !ok {
		t.Fatal("Expected to find a JWT error.")
	}
}
