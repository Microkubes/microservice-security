package chain

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/goadesign/goa"

	"context"
	"net/http/httptest"
)

type Key string

func TestAsGoaMiddleware(t *testing.T) {
	var key Key = "custom-value"
	chain := &Chain{
		MiddlewareList: []SecurityChainMiddleware{
			func(c context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
				return context.WithValue(c, key, 10), rw, nil
			},
		},
	}

	goamid := AsGoaMiddleware(chain)

	if goamid == nil {
		t.Fatal("Expected non-nil Goa middleware")
	}

	req := httptest.NewRequest("GET", "http://example.com", nil)

	goamid(func(c context.Context, rw http.ResponseWriter, req *http.Request) error {
		if c.Value(key) != 10 {
			t.Fatal("Expected the value to be set in context")
		}
		return nil
	})(context.Background(), nil, req)

}

func TestFromGoaMiddleware(t *testing.T) {
	var key Key = "custom-value"
	goaMiddleware := func(hnd goa.Handler) goa.Handler {
		return func(c context.Context, rw http.ResponseWriter, req *http.Request) error {
			return hnd(context.WithValue(c, key, "test-val"), rw, req)
		}
	}

	chain := NewSecurityChain().AddMiddleware(FromGoaMiddleware(goaMiddleware))

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	ctx, _, _, err := chain.Execute(context.Background(), nil, req)
	if err != nil {
		t.Fatal("Expected NOT get errors during chain execute.")
	}
	if ctx == nil {
		t.Fatal("Expected to have a context after chain execute.")
	}
	if ctx.Value(key) != "test-val" {
		t.Fatal("Expected to have the custom value set in context.")
	}
}

func TestToSecurityChainMiddleware(t *testing.T) {
	goaMiddleware := func(hnd goa.Handler) goa.Handler {
		return func(c context.Context, rw http.ResponseWriter, req *http.Request) error {
			return fmt.Errorf("Validation Error")
		}
	}
	chain := NewSecurityChain().AddMiddleware(ToSecurityChainMiddleware("TEST", goaMiddleware))

	req, _ := http.NewRequest("GET", "http://example.com/test", nil)
	ctx, _, _, err := chain.Execute(context.Background(), nil, req)

	if err != nil {
		t.Fatal("Expected NOT to get errors during chain execute.")
	}
	errors := auth.GetSecurityErrors(ctx)
	if errors == nil {
		t.Fatal("Expected to get security errors")
	}
	if _, ok := (*errors)["TEST"]; !ok {
		t.Fatal("Expected to get an error for TEST security middleware.")
	}
}
