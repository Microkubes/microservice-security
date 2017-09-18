package acl

import "github.com/JormungandrK/microservice-security/chain"

type ACLConfiguration struct {
}

type ACLRequest interface{}

type ACLSecurity interface {
	IsAllowed(request ACLRequest) error
}

func NewACLMiddleware() (chain.SecurityChainMiddleware, error) {
	return nil, nil
}
