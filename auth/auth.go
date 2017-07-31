// Package auth exports structure (type) for storing Authorization data and tools
// for accessing and setting the Auth object in provided context.Context.
package auth

import "golang.org/x/net/context"

// Auth stores the Authorization and Authentication data for a particular user/client.
type Auth struct {
	// UserID is the ID of the authenticated user.
	UserID string
	// Username is the username of the authenticated user.
	Username string

	// Roles is the list of roles that the user has claimed and have been authorized by the system.
	Roles []string

	// Organizations is the list of ogranizations that the user belongs to. This is a list of
	// authorized ogranization based on the security claim.
	Organizations []string
}

type key string

const (
	// ContextAuthKey is the context key under which the Auth object is stored in context.Context.
	ContextAuthKey key = "security-auth"
)

// GetAuth retrieves the Auth object from the given context.Context.
// Returns a pointer to the Auth context or nil if no Auth is present in the context.
func GetAuth(ctx context.Context) *Auth {
	auth, ok := ctx.Value(ContextAuthKey).(*Auth)
	if !ok {
		return nil
	}
	return auth
}

// HasAuth checks for existence of Auth object in the given context.Context.
func HasAuth(ctx context.Context) bool {
	auth := GetAuth(ctx)
	return auth != nil
}

// SetAuth sets the pointer to the Auth object in the context.
// Returns context.Context that contains the Auth object.
func SetAuth(ctx context.Context, auth *Auth) context.Context {
	return context.WithValue(ctx, ContextAuthKey, auth)
}

// ClearAuth removes the Auth object from the context.
// Returns a context.Context that does not have a pointer to the Auth object.
func ClearAuth(ctx context.Context) context.Context {
	return context.WithValue(ctx, ContextAuthKey, nil)
}
