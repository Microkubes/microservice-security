package chain

import (
	"net/http"
	"testing"

	"context"
)

type KEY string

func TestContextPassing(t *testing.T) {
	ctx := context.Background()
	modCtx := ctx
	var key KEY = "test-val"
	callCallback(ctx, func(c context.Context) {
		modCtx = context.WithValue(c, key, 10)
	})

	if ctx == modCtx {
		t.Fatal("Context should be changed")
	}

	v := ctx.Value(key)
	if v != nil {
		t.Fatal("Should be empty")
	}

	v = modCtx.Value(key)
	if v == nil {
		t.Fatal("There should be a value in the modified context")
	}
}

func callCallback(original context.Context, callback func(context.Context)) {
	callback(original)
}

func TestNewSecurityChain(t *testing.T) {
	chain := NewSecurityChain()

	if chain == nil {
		t.Fatal("A new SecuirityChain was expected.")
	}
}

func TestAddMiddleware(t *testing.T) {
	chain := &Chain{
		MiddlewareList: []SecurityChainMiddleware{},
	}

	chain.AddMiddleware(func(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
		return ctx, rw, nil
	})

	if len(chain.MiddlewareList) == 0 {
		t.Fatal("Excpected to add the SecurityChainMiddleware.")
	}
}

func TestAddMiddlewareType(t *testing.T) {
	securityMiddlwareRegistar["test"] = func() SecurityChainMiddleware {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
			return ctx, rw, nil
		}
	}

	chain := &Chain{
		MiddlewareList: []SecurityChainMiddleware{},
	}

	_, err := chain.AddMiddlewareType("test")

	if err != nil {
		t.Fatal(err)
	}
	if len(chain.MiddlewareList) == 0 {
		t.Fatal("Excpected to add the SecurityChainMiddleware.")
	}
}

func TestSecurityChainExecute(t *testing.T) {
	type Handler struct {
		name     string
		executed bool
	}

	handlers := make(map[string]bool)

	TestMiddleware := func(name string) SecurityChainMiddleware {
		handlers[name] = false
		return func(c context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
			handlers[name] = true
			return c, rw, nil
		}
	}

	chain := &Chain{
		MiddlewareList: []SecurityChainMiddleware{},
	}

	chain.MiddlewareList = append(chain.MiddlewareList, TestMiddleware("middleware-1"))
	chain.MiddlewareList = append(chain.MiddlewareList, TestMiddleware("middleware-2"))
	chain.MiddlewareList = append(chain.MiddlewareList, TestMiddleware("middleware-3"))

	chain.Execute(context.Background(), nil, nil)

	for name, done := range handlers {
		if !done {
			t.Fatalf("Handler %s not called", name)
		}
	}

}

func TestNewSecurity(t *testing.T) {
	err := NewSecuirty("test-security-1", func() SecurityChainMiddleware {
		return func(context.Context, http.ResponseWriter, *http.Request) (context.Context, http.ResponseWriter, error) {
			return nil, nil, nil
		}
	})
	if err != nil {
		t.Fatal("Error while registering security: ", err)
	}
	if _, ok := securityMiddlwareRegistar["test-security-1"]; !ok {
		t.Fatal("Expected to register the security builder")
	}
}

func TestNewSecurity_DuplicateError(t *testing.T) {
	err := NewSecuirty("test-security-2", func() SecurityChainMiddleware {
		return func(context.Context, http.ResponseWriter, *http.Request) (context.Context, http.ResponseWriter, error) {
			return nil, nil, nil
		}
	})

	if err != nil {
		t.Fatal("Failed to register security", err)
	}

	err = NewSecuirty("test-security-2", func() SecurityChainMiddleware {
		return func(context.Context, http.ResponseWriter, *http.Request) (context.Context, http.ResponseWriter, error) {
			return nil, nil, nil
		}
	})
	if err == nil {
		t.Fatal("Should have returned an error for duplicate registeration.")
	}
}

func TestGetSecurityBuilder(t *testing.T) {
	securityMiddlwareRegistar["test-security-3"] = func() SecurityChainMiddleware {
		return func(context.Context, http.ResponseWriter, *http.Request) (context.Context, http.ResponseWriter, error) {
			return nil, nil, nil
		}
	}
	builder, err := GetSecurityBuilder("test-security-3")
	if err != nil {
		t.Fatal("An error while fetching the builder: ", err)
	}
	if builder == nil {
		t.Fatal("Expected a non-nil builder")
	}
}

func TestAsSecurityMiddleware(t *testing.T) {
	innerChain := &Chain{
		MiddlewareList: []SecurityChainMiddleware{},
	}
	parentChain := &Chain{
		MiddlewareList: []SecurityChainMiddleware{},
	}

	innerMiddlewareCalled := false

	innerMiddleware := func(c context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
		innerMiddlewareCalled = true
		return c, rw, nil
	}
	innerChain.MiddlewareList = append(innerChain.MiddlewareList, innerMiddleware)

	wrappedChainMiddleware := AsSecurityMiddleware(innerChain)

	if wrappedChainMiddleware == nil {
		t.Fatal("Expected to have wrapped the chain in a middleware")
	}

	parentChain.MiddlewareList = append(parentChain.MiddlewareList, wrappedChainMiddleware)

	parentChain.Execute(context.Background(), nil, nil)

	if !innerMiddlewareCalled {
		t.Fatal("Expected the middleware in the inner security chain to be called.")
	}
}
