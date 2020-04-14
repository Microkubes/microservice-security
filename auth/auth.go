// Package auth exports structure (type) for storing Authorization data and tools
// for accessing and setting the Auth object in provided context.Context.
package auth

import "golang.org/x/net/context"

// Auth stores the Authorization and Authentication data for a particular user/client.
type Auth struct {
	// UserID is the ID of the authenticated user.
	UserID string `json:"userId,omitempty"`

	// CustomerID is the ID of the customer to which the authenticated user belongs.
	CustomerID string `json:"customerID,omitempty"`

	// Username is the username of the authenticated user.
	Username string `json:"username,omitempty"`

	// Fullname is the first name and surname of the authenticated user.
	Fullname string `json:"fullname,omitempty"`

	// Email is the email of the authenticated user.
	Email string `json:"email,omitempty"`

	// Roles is the list of roles that the user has claimed and have been authorized by the system.
	Roles []string `json:"roles,omitempty"`

	// Organizations is the list of organizations that the user belongs to. This is a list of
	// authorized ogranization based on the security claim.
	Organizations []string `json:"organizations,omitempty"`

	// Namespaces is the list of namespaces that this user belongs to.
	Namespaces []string `json:"namespaces"`
}

// SecurityErrors holds the errors generated during validation of the request with a
// specific security mechanism (ex. JWT, SAML, OAuth2).
type SecurityErrors map[string]interface{}

// SecurityContext holds pointer to the Auth object and a SecurityErrors.
// It is created for each request and is kept in the context.Context for that request.
type SecurityContext struct {
	*Auth
	Errors SecurityErrors
}

type key string

const (
	// SecurityContextKey is the context key under which the SecurityContext object is stored in context.Context.
	SecurityContextKey key = "security-context"
)

// GetAuth retrieves the Auth object from the given context.Context.
// Returns a pointer to the Auth context or nil if no Auth is present in the context.
func GetAuth(ctx context.Context) *Auth {
	result, ok := ctx.Value(SecurityContextKey).(*SecurityContext)
	if !ok {
		return nil
	}
	return result.Auth
}

// HasAuth checks for existence of Auth object in the given context.Context.
func HasAuth(ctx context.Context) bool {
	auth := GetAuth(ctx)
	return auth != nil
}

// SetAuth sets the pointer to the Auth object in the context.
// Returns context.Context that contains the Auth object.
func SetAuth(ctx context.Context, auth *Auth) context.Context {
	secContext, ok := ctx.Value(SecurityContextKey).(*SecurityContext)
	if !ok {
		errors := make(SecurityErrors)
		secContext = &SecurityContext{
			Errors: errors,
		}
	}
	secContext.Auth = auth
	return context.WithValue(ctx, SecurityContextKey, secContext)
}

// ClearSecurityContext removes the SecurityContext object from the context.
// Returns a context.Context that does not have a pointer to the SecurityContext object.
func ClearSecurityContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, SecurityContextKey, nil)
}

// GetSecurityContext returns the SecurityContext from the given context.
// If not found, it returns nil.
func GetSecurityContext(ctx context.Context) *SecurityContext {
	sc, ok := ctx.Value(SecurityContextKey).(*SecurityContext)
	if !ok {
		return nil
	}
	return sc
}

// GetSecurityErrors returns the SecurityErrors map from the SecurityContext in the
// given context.
// If no SecurityContext exists in the current context, it returns nil.
func GetSecurityErrors(ctx context.Context) *SecurityErrors {
	sc := GetSecurityContext(ctx)
	if sc == nil {
		return nil
	}
	return &sc.Errors
}

// SetSecurityError sets an error for the given security type in the SecurityContext.
// If there is no SecurityContext in the given context, a new one is created implicitly.
func SetSecurityError(ctx context.Context, secType string, err interface{}) context.Context {
	sc, ok := ctx.Value(SecurityContextKey).(*SecurityContext)
	if !ok {
		sc = &SecurityContext{
			Errors: make(SecurityErrors),
		}
		ctx = context.WithValue(ctx, SecurityContextKey, sc)
	}

	sc.Errors[secType] = err

	return ctx
}
