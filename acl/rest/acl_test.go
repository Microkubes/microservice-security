package rest

import (
	"fmt"
	"testing"

	"golang.org/x/net/context"

	"github.com/Microkubes/microservice-security/acl"
	"github.com/Microkubes/microservice-security/acl/rest/app"
	"github.com/Microkubes/microservice-security/acl/rest/app/test"
	"github.com/Microkubes/microservice-security/auth"
	"github.com/goadesign/goa"
	"github.com/ory/ladon"
	uuid "github.com/satori/go.uuid"
)

type DummyLadonManager struct {
	Policies map[string]ladon.Policy
	DoCreate func(ladon.Policy) error
	DoUpdate func(existing ladon.Policy, policy ladon.Policy) error
	DoGet    func(string, ladon.Policy) (ladon.Policy, error)
	DoDelete func(string, ladon.Policy) error
	//DoGetAllfunc            func(int64, int64) (ladon.Policies, error)
	//DoFindRequestCandidates func(*ladon.Request) (ladon.Policies, error)
}

func (d *DummyLadonManager) Create(policy ladon.Policy) error {
	d.Policies[policy.GetID()] = policy
	if d.DoCreate != nil {
		return d.DoCreate(policy)
	}
	return nil
}

func (d *DummyLadonManager) Update(policy ladon.Policy) error {
	existing, ok := d.Policies[policy.GetID()]
	if !ok {
		return fmt.Errorf("not found")
	}
	if d.DoUpdate != nil {
		return d.DoUpdate(existing, policy)
	}
	return nil
}

func (d *DummyLadonManager) Get(id string) (ladon.Policy, error) {
	policy, ok := d.Policies[id]
	if d.DoGet != nil {
		return d.DoGet(id, policy)
	}
	if !ok {
		return nil, nil
	}
	return policy, nil
}

func (d *DummyLadonManager) Delete(id string) error {
	policy, ok := d.Policies[id]
	if d.DoDelete != nil {
		return d.DoDelete(id, policy)
	}
	if !ok {
		return fmt.Errorf("not-found")
	}
	delete(d.Policies, id)
	return nil
}

func (d *DummyLadonManager) GetAll(limit, offset int64) (ladon.Policies, error) {
	return nil, nil
}

func (d *DummyLadonManager) FindRequestCandidates(r *ladon.Request) (ladon.Policies, error) {
	return nil, nil
}

func (d *DummyLadonManager) FindPoliciesForSubject(subject string) (ladon.Policies, error) {
	return nil, nil
}

func (d *DummyLadonManager) FindPoliciesForResource(resource string) (ladon.Policies, error) {
	return nil, nil
}

func contains(array []string, value string) bool {
	for _, v := range array {
		if v == value {
			return true
		}
	}
	return false
}

func TestCreatePolicyAclBadRequest(t *testing.T) {
	service := goa.New("")

	aclController, err := NewACLController(service, &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
	})

	if err != nil {
		t.Fatal(err)
	}

	payload := &app.ACLPolicyPayload{
		// missing all values must create bad request
	}

	test.CreatePolicyAclBadRequest(t, context.Background(), service, aclController, payload)
}

func TestCreatePolicyAclCreated(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
	}
	aclController, err := NewACLController(service, manager)

	if err != nil {
		t.Fatal(err)
	}

	description := ""

	randUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	id := randUUID.String()
	payload := &app.ACLPolicyPayload{
		Actions:     []string{"api:read"},
		Description: &description,
		Effect:      "AllowAccess",
		ID:          &id,
		Resources:   []string{"/resource/1"},
		Subjects:    []string{"user1"},
	}

	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	test.CreatePolicyAclCreated(t, ctx, service, aclController, payload)
	if len(manager.Policies) == 0 {
		t.Fatal("Expected to add policy")
	}
}

func TestCreatePolicyAclInternalServerError(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
		DoCreate: func(policy ladon.Policy) error {
			if contains([]string{"admin-access-allow-all", "owner-access-allow-all"}, policy.GetID()) {
				return nil
			}
			return fmt.Errorf("simulated internal error")
		},
	}
	aclController, err := NewACLController(service, manager)

	if err != nil {
		t.Fatal(err)
	}

	description := ""

	randUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	id := randUUID.String()
	payload := &app.ACLPolicyPayload{
		Actions:     []string{"api:read"},
		Description: &description,
		Effect:      "AllowAccess",
		ID:          &id,
		Resources:   []string{"/resource/1"},
		Subjects:    []string{"user1"},
	}

	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	test.CreatePolicyAclInternalServerError(t, ctx, service, aclController, payload)
}

func TestDeletePolicyAclInternalServerError(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{
			"policy-0": &ladon.DefaultPolicy{},
		},
		DoDelete: func(id string, policy ladon.Policy) error {
			return fmt.Errorf("simulated error")
		},
	}

	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)

	if err != nil {
		t.Fatal(err)
	}

	test.DeletePolicyAclInternalServerError(t, ctx, service, aclController, "policy-0")

}

func TestDeletePolicyAclNotFound(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
		DoDelete: func(id string, policy ladon.Policy) error {
			return fmt.Errorf("simulated error")
		},
	}

	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)

	if err != nil {
		t.Fatal(err)
	}

	test.DeletePolicyAclNotFound(t, ctx, service, aclController, "policy-0")
}

func TestDeletePolicyAclOK(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{
			"policy-0": &ladon.DefaultPolicy{},
		},
	}

	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	test.DeletePolicyAclOK(t, ctx, service, aclController, "policy-0")

	if len(manager.Policies) > 2 { // just the default ACL policies shoudl be present
		t.Fatal("Policy not deleted")
	}
}

func TestGetAclInternalServerError(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{
			"policy-0": &ladon.DefaultPolicy{},
		},
		DoGet: func(id string, policy ladon.Policy) (ladon.Policy, error) {
			if contains([]string{"admin-access-allow-all", "owner-access-allow-all"}, id) {
				return policy, nil
			}
			return nil, fmt.Errorf("simulated error")
		},
	}

	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	test.GetAclInternalServerError(t, ctx, service, aclController, "policy-0")
}

func TestGetAclNotFound(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
	}

	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	test.GetAclNotFound(t, ctx, service, aclController, "policy-0")
}

func TestGetAclOK(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{
			"policy-0": &ladon.DefaultPolicy{
				Actions: []string{"api:read"},
				Conditions: ladon.Conditions{
					"organizations": &acl.AllowedPatternsCondition{
						Name:   "OrganizationsCondition",
						Values: []string{"a", "b", "c"},
					},
				},
				Description: "Test Policy",
				Effect:      "AllowAccess",
				ID:          "policy-0",
				Resources:   []string{"/resource"},
				Subjects:    []string{"user-1"},
			},
		},
	}

	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	test.GetAclOK(t, ctx, service, aclController, "policy-0")
}

func TestManageAccessAclBadRequest(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
	}
	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	payload := &app.AccessPolicyPayload{}

	test.ManageAccessAclBadRequest(t, ctx, service, aclController, payload)

}

func TestManageAccessAclInternalServerError(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
		DoCreate: func(policy ladon.Policy) error {
			if contains([]string{"admin-access-allow-all", "owner-access-allow-all"}, policy.GetID()) {
				return nil
			}
			return fmt.Errorf("simulated-error")
		},
	}
	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	description := ""
	payload := &app.AccessPolicyPayload{
		Allow:         true,
		Description:   &description,
		Organizations: []string{"org1"},
		Resources:     []string{"/resource"},
		Roles:         []string{"admin"},
		Scopes:        []string{"api:read"},
		Users:         []string{"user2"},
	}

	test.ManageAccessAclInternalServerError(t, ctx, service, aclController, payload)
}

func TestManageAccessAclOK(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
	}
	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	description := ""
	payload := &app.AccessPolicyPayload{
		Allow:         true,
		Description:   &description,
		Organizations: []string{"org1"},
		Resources:     []string{"/resource"},
		Roles:         []string{"admin"},
		Scopes:        []string{"api:read"},
		Users:         []string{"user2"},
	}

	test.ManageAccessAclOK(t, ctx, service, aclController, payload)
	if len(manager.Policies) == 0 {
		t.Fatal("ACL Policy was not created")
	}

	for policyID, policy := range manager.Policies {
		if contains([]string{"admin-access-allow-all", "owner-access-allow-all"}, policyID) {
			continue
		}
		if !policy.AllowAccess() {
			t.Fatal("Access should be allowed")
		}

		if cond, ok := policy.GetConditions()["organizations"]; ok {
			if cond.GetName() != "OrganizationsCondition" {
				t.Fatal("Invalid organizations condition in ACL Policy")
			}
		} else {
			t.Fatal("No organizations condition set")
		}

		if cond, ok := policy.GetConditions()["roles"]; ok {
			if cond.GetName() != "RolesCondition" {
				t.Fatal("Invalid roles condition in ACL policy")
			}
		} else {
			t.Fatal("No roles condition set")
		}
		break
	}
}

func TestUpdatePolicyAclBadRequest(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
	}
	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	description := ""

	randUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	id := randUUID.String()
	payload := &app.ACLPolicyPayload{
		Actions:     []string{"api:read"},
		Description: &description,
		//Effect:      "AllowAccess",
		ID:        &id,
		Resources: []string{"/resource/1"},
		Subjects:  []string{"user1"},
	}

	test.UpdatePolicyAclBadRequest(t, ctx, service, aclController, "policy-0", payload)
}

func TestUpdatePolicyAclInternalServerError(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{
			"policy-0": &ladon.DefaultPolicy{
				Effect: "allow",
			},
		},
		DoUpdate: func(existing ladon.Policy, policy ladon.Policy) error {
			return fmt.Errorf("simulated error")
		},
	}
	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	description := ""

	randUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	id := randUUID.String()
	payload := &app.ACLPolicyPayload{
		Actions:     []string{"api:read"},
		Description: &description,
		Effect:      "AllowAccess",
		ID:          &id,
		Resources:   []string{"/resource/1"},
		Subjects:    []string{"user1"},
	}

	test.UpdatePolicyAclInternalServerError(t, ctx, service, aclController, "policy-0", payload)
}

func TestUpdatePolicyAclNotFound(t *testing.T) {
	service := goa.New("")
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{},
	}
	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	description := ""

	randUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	id := randUUID.String()
	payload := &app.ACLPolicyPayload{
		Actions:     []string{"api:read"},
		Description: &description,
		Effect:      "AllowAccess",
		ID:          &id,
		Resources:   []string{"/resource/1"},
		Subjects:    []string{"user1"},
	}

	test.UpdatePolicyAclNotFound(t, ctx, service, aclController, "policy-0", payload)
}

func TestUpdatePolicyAclOK(t *testing.T) {
	service := goa.New("")
	updateCalled := false
	manager := &DummyLadonManager{
		Policies: map[string]ladon.Policy{
			"policy-0": &ladon.DefaultPolicy{
				Effect: "allow",
			},
		},
		DoUpdate: func(existing ladon.Policy, policy ladon.Policy) error {
			updateCalled = true
			return nil
		},
	}
	ctx := auth.SetAuth(context.Background(), &auth.Auth{
		Username:      "test-user",
		UserID:        "user-001",
		Roles:         []string{"user"},
		Organizations: []string{"org1"},
	})

	aclController, err := NewACLController(service, manager)
	if err != nil {
		t.Fatal(err)
	}

	description := ""

	randUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	id := randUUID.String()
	payload := &app.ACLPolicyPayload{
		Actions:     []string{"api:read"},
		Description: &description,
		Effect:      "AllowAccess",
		ID:          &id,
		Resources:   []string{"/resource/1"},
		Subjects:    []string{"user1"},
	}

	test.UpdatePolicyAclOK(t, ctx, service, aclController, "policy-0", payload)
	if !updateCalled {
		t.Fatal("Update of policy was not called")
	}
}
