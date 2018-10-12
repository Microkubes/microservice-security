package db

import (
	"github.com/JormungandrK/backends"
)

type ACLRepository interface {
	backends.Repository
	FindPolicies(filter map[string]string) ([]*PolicyRecord, error)
}
