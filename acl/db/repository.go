package db

import (
	"github.com/JormungandrK/backends"
)

type ACLRepository interface {
	backends.Repository
	GetPolicies()
}
