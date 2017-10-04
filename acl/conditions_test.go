package acl

import (
	"testing"

	"github.com/ory/ladon"
)

func TestNewCondition_RolesCondition(t *testing.T) {

	cond, err := NewCondition("RolesCondition", []string{"user"})
	if err != nil {
		t.Fatal(err)
	}
	if cond == nil {
		t.Fatal("Expected condition")
	}

	if !cond.Fulfills("user", &ladon.Request{
		Context: ladon.Context{
			"roles": []string{"user"},
		},
	}) {
		t.Fatal("Should pass, but failed instead")
	}

	if cond.Fulfills("admin", &ladon.Request{
		Context: ladon.Context{
			"roles": []string{"admin"},
		},
	}) {
		t.Fatal("Should fail, but passed instead")
	}
}

func TestNewCondition_ScopesCondition(t *testing.T) {

	cond, err := NewCondition("ScopesCondition", []string{"api:read"})
	if err != nil {
		t.Fatal(err)
	}
	if cond == nil {
		t.Fatal("Expected condition")
	}

	if !cond.Fulfills("api:read", &ladon.Request{
		Context: ladon.Context{
			"scopes": []string{"api:read"},
		},
	}) {
		t.Fatal("Should pass, but failed instead")
	}

	if cond.Fulfills("api:write", &ladon.Request{
		Context: ladon.Context{
			"scopes": []string{"api:write"},
		},
	}) {
		t.Fatal("Should fail, but passed instead")
	}
}
