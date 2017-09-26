package acl

import (
	"net/http"
	"testing"

	"context"

	"github.com/JormungandrK/microservice-security/auth"
	"github.com/ory/ladon"

	manager "github.com/ory/ladon/manager/memory"
)

func TestIsAllowed(t *testing.T) {
	pol := &ladon.DefaultPolicy{
		ID:          "aaa-bbb-ccc",
		Description: "Test Policy",
		Subjects:    []string{"role:user", "role:admin", "userone"},
		Resources:   []string{"/user/<.+>"},
		Actions:     []string{"api:read"},
		Effect:      ladon.AllowAccess,
	}

	warden := ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	err := warden.Manager.Create(pol)
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.WithValue(context.Background(), ladonWardenKey, &warden)
	req, err := http.NewRequest("GET", "http://example.com/user/10", nil)
	if err != nil {
		t.Fatal(err)
	}
	err = IsAllowed(ctx, req, "userone", AccessContext{
		"userId":        "10",
		"username":      "userone",
		"roles":         []string{"user"},
		"organizations": []string{"org1"},
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestNewACLMiddleware(t *testing.T) {
	pol := &ladon.DefaultPolicy{
		ID:          "aaa-bbb-ccc",
		Description: "Test Policy",
		Subjects:    []string{"role:user", "role:admin", "userone"},
		Resources:   []string{"/user/<.+>"},
		Actions:     []string{"api:read"},
		Effect:      ladon.AllowAccess,
	}

	manager := manager.NewMemoryManager()
	err := manager.Create(pol)
	if err != nil {
		t.Fatal(err)
	}

	authObj := auth.Auth{
		UserID:        "10",
		Username:      "userone",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	}

	aclMiddleware, err := NewACLMiddleware(manager)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "http://example.com/user/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, _, err := aclMiddleware(auth.SetAuth(context.Background(), &authObj), nil, req)
	if err != nil {
		t.Fatal(err)
	}

	warden := ctx.Value(ladonWardenKey)
	if warden == nil {
		t.Fatal("Ladon Warden was expected in the chain context.")
	}

}
