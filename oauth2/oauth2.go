package oauth2

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"github.com/JormungandrK/microservice-security/chain"
	"github.com/JormungandrK/microservice-security/auth"
	"github.com/goadesign/goa"
)

// OAUTH2SecurityType is the name of the security type (JWT, OAUTH2, SAML...)
const OAUTH2SecurityType = "OAUTH2"

type TokenMedia struct {
	AccessToken   string
	UserID        string
	UserName      string
	Roles         []string
	Organizations []string
}

type Oauth2Repository interface {
	GetToken(token string) (*TokenMedia, error)
}

func NewOAuth2Security(db Oauth2Repository) chain.SecurityChainMiddleware {
	goaMiddleware := NewOAuth2SecurityMiddleware(db)
	return chain.ToSecurityChainMiddleware(OAUTH2SecurityType, goaMiddleware)
}

// NewOAuth2Middleware creates a middleware that checks for the presence of an authorization header
// and validates its content.
func NewOAuth2SecurityMiddleware(db Oauth2Repository) goa.Middleware {
	return func(h goa.Handler) goa.Handler {
		return func(ctx context.Context, rw http.ResponseWriter, req *http.Request) error {
			token := req.Header["Authorization"]
			if token == nil {
				return goa.ErrUnauthorized("missing auth header")
			}
			tok := token[0]
			if len(tok) < 9 || !strings.HasPrefix(tok, "Bearer ") {
				return goa.ErrUnauthorized("invalid auth header")
			}
			tok = tok[7:]

			// Validate token here against value stored in DB for example
			// if tok != TheAccessToken {
			// 	return ErrUnauthorized("invalid token")
			// }

			authObj := &auth.Auth{
				Roles:         []string{"admin", "user"},
				Organizations: []string{"org1", "org2"},
				Username:      "test-user",
				UserID:        "599316bbf456208abcbcc186",
			}
			return h(auth.SetAuth(ctx, authObj), rw, req)
		}
	}
}

// DB emulates a database driver using in-memory data structures.
type DB struct {
	sync.Mutex
	tokens map[string]*TokenMedia
}

// New initializes a new "DB" with dummy data.
func NewDB() *DB {
	tokenEntry := &TokenMedia{
		AccessToken:   "qweqc461f9f8eb02aae053f3",
		UserID:        "599316bbf456208abcbcc186",
		UserName:      "test-user",
		Roles:         []string{"admin", "user"},
		Organizations: []string{"org1", "org2"},
	}
	return &DB{tokens: map[string]*TokenMedia{"qweqc461f9f8eb02aae053f3": tokenEntry}}
}

// GetToken mock implementation
func (db *DB) GetToken(token string) (*TokenMedia, error) {
	db.Lock()
	defer db.Unlock()

	tokenEntry, ok := db.tokens[token]
	if !ok {
		return nil, goa.ErrInternal("Internal error")
	}

	return tokenEntry, nil
}
