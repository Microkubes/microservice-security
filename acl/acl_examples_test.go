package acl

import (
	"fmt"
	"testing"

	"github.com/ory/ladon"
	manager "github.com/ory/ladon/manager/memory"
)

func TestLadonWarden(t *testing.T) {
	pol := &ladon.DefaultPolicy{
		ID:          "aaa-bbb-ccc",
		Description: "Test Policy",
		Subjects:    []string{"role:user", "role:admin", "pajo"},
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

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read", // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me", // the actual resource asked
		Subject:  "pajo",     // username and/or role
	})

	if err != nil {
		t.Fatal("Access Denied:", err)
	}
	t.Log("Access Granted!")

}

// Usecases:
// 1. Allow/Disallow access by role
// 2. Allow/Disallow access by scope
// 3. Allow access to users from organization
// 4. Allow access to specific users only
// 5. Combine any two restrictions (roles + scope, organization but disallow specific user etc)
// 6. Allow only the owner to access

type HasRoleCondition struct {
	Allowed []string
}

// Fulfills returns true if the request's subject is equal to the given value string
func (c *HasRoleCondition) Fulfills(value interface{}, r *ladon.Request) bool {
	roles, ok := value.([]string)
	if !ok {
		return false
	}

	for _, role := range roles {
		for _, allowed := range c.Allowed {
			if role == allowed {
				return true
			}
		}
	}

	return false
}

// GetName returns the condition's name.
func (c *HasRoleCondition) GetName() string {
	return "HasRoleCondition"
}

func TestRoleAccess(t *testing.T) {
	pol := &ladon.DefaultPolicy{
		ID:          "role-access-001",
		Description: "Test access by role",
		Subjects:    []string{"test-user"}, // allow anyone with role user to access anything under user
		Resources:   []string{"/user/<.+>"},
		Actions:     []string{"api:read"},
		Effect:      ladon.AllowAccess,
		Conditions: ladon.Conditions{
			"roles": &HasRoleCondition{
				Allowed: []string{"user"},
			},
		},
	}

	warden := ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	err := warden.Manager.Create(pol)
	if err != nil {
		t.Fatal(err)
	}

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"roles": []string{"user"},
		},
	})

	if err != nil {
		t.Fatal("Access Denied:", err)
	}
	t.Log("Access Granted!")

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"roles": []string{"guest"},
		},
	})

	if err == nil {
		t.Fatal("Expected to deny the request")
	}
	t.Log(err.Error())
}

type CustomCondition struct {
	name   string
	testfn func(value interface{}, r *ladon.Request) bool
}

func (c *CustomCondition) Fulfills(value interface{}, r *ladon.Request) bool {
	if c.testfn == nil {
		return false
	}
	return c.testfn(value, r)
}

// GetName returns the condition's name.
func (c *CustomCondition) GetName() string {
	return c.name
}

func NewCustomCondition(name string, testfn func(value interface{}, r *ladon.Request) bool) *CustomCondition {
	return &CustomCondition{
		name:   name,
		testfn: testfn,
	}
}

func TestAllowByScope(t *testing.T) {
	pol := &ladon.DefaultPolicy{
		ID:          "scope-access-001",
		Description: "Test access by scope",
		Subjects:    []string{"test-user"}, // allow anyone with role user to access anything under user
		Resources:   []string{"/user/<.+>"},
		Actions:     []string{"api:read"},
		Effect:      ladon.AllowAccess,
		Conditions: ladon.Conditions{
			"scope": NewCustomCondition("ACLScope", func(value interface{}, r *ladon.Request) bool {
				scope, ok := value.(string)
				if !ok {
					return false
				}
				return scope == "api:read" // allow only read.
			}),
		},
	}

	warden := ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	err := warden.Manager.Create(pol)
	if err != nil {
		t.Fatal(err)
	}

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"scope": "api:read",
		},
	})

	if err != nil {
		t.Fatal("Access Denied:", err)
	}
	t.Log("Access Granted!")

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"scope": "api:write", // map from auth.Auth
		},
	})

	if err == nil {
		t.Fatal("Write access should be denied")
	}
	t.Log(err.Error())
}

func TestAccessByOrganization(t *testing.T) {
	pol := &ladon.DefaultPolicy{
		ID:          "scope-access-001",
		Description: "Test access by scope",
		Subjects:    []string{"test-user"}, // allow anyone with role user to access anything under user
		Resources:   []string{"/user/<.+>"},
		Actions:     []string{"api:read"},
		Effect:      ladon.AllowAccess,
		Conditions: ladon.Conditions{
			"organizations": NewCustomCondition("OrganizationsScope", func(value interface{}, r *ladon.Request) bool {
				organizations, ok := value.([]string)
				if !ok {
					return false
				}
				for _, organization := range organizations {
					if organization == "allowed-organization" {
						return true
					}
				}
				return false
			}),
		},
	}

	warden := ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	err := warden.Manager.Create(pol)
	if err != nil {
		t.Fatal(err)
	}

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"organizations": []string{"organization-1", "allowed-organization"},
		},
	})

	if err != nil {
		t.Fatal("Access Denied:", err)
	}
	t.Log("Access Granted!")

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"organizations": []string{"organization-1", "organization-2"}, // but no "allowed-organization"
		},
	})

	if err == nil {
		t.Fatal("Access should be denied")
	}
	t.Log(err.Error())
}

func TestAccessBySpecificUser(t *testing.T) {
	pol := &ladon.DefaultPolicy{
		ID:          "scope-access-001",
		Description: "Test access by scope",
		Subjects:    []string{"test-user"}, // allow anyone with role user to access anything under user
		Resources:   []string{"/user/<.+>"},
		Actions:     []string{"api:read"},
		Effect:      ladon.AllowAccess,
		Conditions: ladon.Conditions{
			"username": &ladon.EqualsSubjectCondition{},
		},
	}

	warden := ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	err := warden.Manager.Create(pol)
	if err != nil {
		t.Fatal(err)
	}

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"username": "test-user",
		},
	})

	if err != nil {
		t.Fatal("Access Denied:", err)
	}
	t.Log("Access Granted!")

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"username": "not-the-same-user",
		},
	})

	if err == nil {
		t.Fatal("Access should be denied")
	}
	t.Log(err.Error())
}

func TestAllowOnlySpecificRoleFromSpecificOrganization(t *testing.T) {
	pol := &ladon.DefaultPolicy{
		ID:          "composite-access-001",
		Description: "Test access by scope",
		Subjects:    []string{"<.+>"}, // allow anyone with role user to access anything under user
		Resources:   []string{"/jormungandr/admin/<.+>"},
		Actions:     []string{"api:read", "api:write"},
		Effect:      ladon.AllowAccess,
		Conditions: ladon.Conditions{
			"role": NewCustomCondition("RoleCheck", func(value interface{}, r *ladon.Request) bool {
				role, ok := value.(string)
				if !ok {
					return false
				}
				return role == "admin"
			}),
			"organizations": NewCustomCondition("OrganizationCheck", func(value interface{}, r *ladon.Request) bool {
				organizations, ok := value.([]string)
				if !ok {
					return false
				}
				for _, org := range organizations {
					if org == "Jormungandr" {
						return true
					}
				}
				return false
			}),
		},
	}

	warden := ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	err := warden.Manager.Create(pol)
	if err != nil {
		t.Fatal(err)
	}

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:write",                   // mapped from the actual request (scope + HTTP action)
		Resource: "/jormungandr/admin/add-user", // the actual resource asked
		Subject:  "jormungadrAdmin",             // username and/or role,
		Context: ladon.Context{
			"role":          "admin",
			"organizations": []string{"Jormungandr", "Other"},
		},
	})

	if err != nil {
		t.Fatal("Access Denied:", err)
	}
	t.Log("Access Granted!")

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:write",                   // mapped from the actual request (scope + HTTP action)
		Resource: "/jormungandr/admin/add-user", // the actual resource asked
		Subject:  "jormungadrAdmin",             // username and/or role,
		Context: ladon.Context{
			"role":          "user",
			"organizations": []string{"Jormungandr", "Other"},
		},
	})

	if err == nil {
		t.Fatal("Access should be denied")
	}
	t.Log(err.Error())

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:write",                   // mapped from the actual request (scope + HTTP action)
		Resource: "/jormungandr/admin/add-user", // the actual resource asked
		Subject:  "jormungadrAdmin",             // username and/or role,
		Context: ladon.Context{
			"role":          "admin",
			"organizations": []string{"NotTheCorrectOne", "Other"},
		},
	})

	if err == nil {
		t.Fatal("Access should be denied")
	}
	t.Log(err.Error())
}

func TestAllowSpecificRole_OR_SpecificOrganization(t *testing.T) {
	rolePolicy := &ladon.DefaultPolicy{
		ID:          "role-policy",
		Description: "Test access by role",
		Subjects:    []string{"<.+>"}, // allow anyone with role user to access anything under user
		Resources:   []string{"/jormungandr/admin/<.+>"},
		Actions:     []string{"api:read", "api:write"},
		Effect:      ladon.AllowAccess,
		Conditions: ladon.Conditions{
			"role": NewCustomCondition("RoleCheck", func(value interface{}, r *ladon.Request) bool {
				role, ok := value.(string)
				if !ok {
					return false
				}
				return role == "admin"
			}),
		},
	}

	organizationPolicy := &ladon.DefaultPolicy{
		ID:          "organization-policy",
		Description: "Test access by scope",
		Subjects:    []string{"<.+>"}, // allow anyone with role user to access anything under user
		Resources:   []string{"/jormungandr/admin/<.+>"},
		Actions:     []string{"api:read", "api:write"},
		Effect:      ladon.AllowAccess,
		Conditions: ladon.Conditions{
			"organizations": NewCustomCondition("OrganizationCheck", func(value interface{}, r *ladon.Request) bool {
				organizations, ok := value.([]string)
				if !ok {
					return false
				}
				for _, org := range organizations {
					if org == "Jormungandr" {
						return true
					}
				}
				return false
			}),
		},
	}

	warden := ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	err := warden.Manager.Create(rolePolicy)
	if err != nil {
		t.Fatal("Failed to register role policy", err)
	}
	err = warden.Manager.Create(organizationPolicy)
	if err != nil {
		t.Fatal("Failed to register organization policy", err)
	}

	// allow user that is "admin"
	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:write",                   // mapped from the actual request (scope + HTTP action)
		Resource: "/jormungandr/admin/add-user", // the actual resource asked
		Subject:  "jormungadrAdmin",             // username and/or role,
		Context: ladon.Context{
			"role": "admin",
		},
	})

	if err != nil {
		t.Fatal("Access Denied:", err)
	}
	t.Log("Access Granted!")

	// allow anyone from Jormungandr
	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:write",                   // mapped from the actual request (scope + HTTP action)
		Resource: "/jormungandr/admin/add-user", // the actual resource asked
		Subject:  "jormungadrAdmin",             // username and/or role,
		Context: ladon.Context{
			"organizations": []string{"Jormungandr", "Other"},
		},
	})

	if err != nil {
		t.Fatal("Access Denied:", err)
	}
	t.Log("Access Granted!")

	// Disallow anyone else
	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:write",                   // mapped from the actual request (scope + HTTP action)
		Resource: "/jormungandr/admin/add-user", // the actual resource asked
		Subject:  "jormungadrAdmin",             // username and/or role,
		Context: ladon.Context{
			"role":          "user",
			"organizations": []string{"NotJormungandr", "Other"},
		},
	})

	if err == nil {
		t.Fatal("Access Should be denied on anyone that is not an admin or not part of Jormungandr")
	}
}

func TestAllowOnlyOwner(t *testing.T) {
	pol := &ladon.DefaultPolicy{
		ID:          "scope-access-001",
		Description: "Test access by scope",
		Subjects:    []string{"test-user"}, // allow anyone with role user to access anything under user
		Resources:   []string{"/user/<.+>"},
		Actions:     []string{"api:read"},
		Effect:      ladon.AllowAccess,
		Conditions: ladon.Conditions{
			//"owner": &ladon.EqualsSubjectCondition{},
			"owner": &OwnerCondition{},
		},
	}

	warden := ladon.Ladon{
		Manager: manager.NewMemoryManager(),
	}
	err := warden.Manager.Create(pol)
	if err != nil {
		t.Fatal(err)
	}

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"owner": "test-user", // this is populated from DB, but NOT in the middleare
		},
	})

	if err != nil {
		t.Fatal("Access Denied:", err)
	}
	t.Log("Access Granted!")

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context: ladon.Context{
			"owner": "not-the-same-user",
		},
	})

	if err == nil {
		t.Fatal("Access should be denied")
	}
	t.Log(err.Error())

	err = warden.IsAllowed(&ladon.Request{
		Action:   "api:read",  // mapped from the actual request (scope + HTTP action)
		Resource: "/user/me",  // the actual resource asked
		Subject:  "test-user", // username and/or role,
		Context:  ladon.Context{},
	})
	fmt.Println("No owner set: ", err)
}
