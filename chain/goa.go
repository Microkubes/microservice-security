package chain

import (
	"net/http"

	"context"

	"github.com/goadesign/goa"
)

// AsGoaMiddleware wraps a SecurityChain as a goa.Middleware that can later be used
// with goa service and registered as a standard goa.Middleware.
func AsGoaMiddleware(chain SecurityChain) goa.Middleware {
	return func(hnd goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			ctx, rw, req, err := chain.Execute(ctx, rw, req)
			if err != nil {
				return err
			}
			return hnd(ctx, rw, req)
		}
	}
}

// FromGoaMiddleware wraps a goa.Middleware into a SecurityChainMiddleware.
// This SecurityChainMiddleware can then be used as a standard SecurityChainMiddleware
// in the security chain.
// This is useful for wrapping the generated security middlewares of goadesign into
// a SecurityChainMiddleware and registered with the full security chain.
func FromGoaMiddleware(middleware goa.Middleware) SecurityChainMiddleware {

	return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) (context.Context, http.ResponseWriter, error) {
		pCtx := ctx
		pRw := rw
		err := middleware(func(c context.Context, w http.ResponseWriter, r *http.Request) error {
			// this handler is called AFTER the goa middleware executes and as arguments
			// gets the modified context and possibly other instance of ResponseWriter.
			// We want to pass these modified versions back to our chain.
			pCtx = c
			pRw = w
			return nil
		})(ctx, rw, req)

		if err != nil {
			return pCtx, pRw, err
		}
		return pCtx, pRw, nil // return back the modified context and ResponseWriter
	}
}
