package db

import (
	"github.com/JormungandrK/backends"
)

// ACLRepository extends the backends.Repository interface by adding new functions
// for handling ACL Policies.
type ACLRepository interface {
	// Repository is the wrapped backends.Repository.
	backends.Repository

	// FindPolicies performs lookup for policies that match the input filter.
	FindPolicies(filter map[string]string) ([]*PolicyRecord, error)
}
