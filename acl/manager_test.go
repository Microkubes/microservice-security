package acl

import (
	"log"
	"os"
	"testing"

	"github.com/Microkubes/backends"

	"github.com/Microkubes/microservice-security/acl/db"
	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-tools/config"
	"github.com/ory/ladon"
	"github.com/ory/ladon/compiler"
	uuid "github.com/satori/go.uuid"
)

func getEnv(varName, defaultValue string) string {
	value := os.Getenv(varName)
	if value == "" {
		return defaultValue
	}
	return value
}

func loadDBConfig() *config.DBConfig {
	dbc := &config.DBConfig{
		DBName: getEnv("TST_DBTYPE", "mongodb"),
		DBInfo: config.DBInfo{
			DatabaseName: getEnv("TST_DBNAME", "testdb"),
			Host:         getEnv("TST_DBHOST", "mongo:27017"),
			Username:     getEnv("TST_DBUSER", "restapi"),
			Password:     getEnv("TST_DBPASS", "restapi"),
		},
	}

	if dbc.DBName == "dynamodb" {
		log.Println("DynamoDB backend.")
		dbc.AWSRegion = getEnv("TST_AWSREGION", "us-east")
		dbc.AWSEndpoint = getEnv("TST_AWSENDPOINT", "")
		dbc.AWSCredentials = getEnv("TST_AWSCREDS", "")
		dbc.AWSSecretKeyID = getEnv("TST_AWSSECRETKEYID", "")
		dbc.AWSSecretAccessKey = getEnv("TST_AWSSECRETACCESSKEY", "")
		dbc.AWSSessionToken = getEnv("TST_AWSSESSIONTOKEN", "")
	}

	return dbc
}

func TestCompileRegex(t *testing.T) {
	policy := ladon.DefaultPolicy{}
	compiled, err := compiler.CompileRegex("test.<a|b>", policy.GetStartDelimiter(), policy.GetEndDelimiter())
	if err != nil {
		t.Fatal(err)
	}
	println(compiled.String())
}

func TestCreatePolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	manager, cleanup, err := NewBackendLadonManager(loadDBConfig())
	if err != nil {
		t.Fatal(err)
	}

	randUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	id := randUUID.String()

	if cleanup != nil {
		defer func() {
			//manager.Collection.Remove(bson.M{"id": id})
			manager.getRepository().DeleteOne(backends.NewFilter().Match("id", id))
			cleanup()
		}()
	}

	authObj := auth.Auth{
		Organizations: []string{"org1", "org2"},
		Roles:         []string{"user"},
		UserID:        "id-1",
		Username:      "username",
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read", "api:write"},
		Description: "Description",
		Effect:      ladon.AllowAccess,
		ID:          id,
		Resources:   []string{"/user/<.+>", "/admin"},
		Subjects:    []string{"username", "another-user"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	resultPolicy := db.PolicyRecord{}

	if _, err = manager.getRepository().GetOne(backends.NewFilter().Match("id", id), &resultPolicy); err != nil {
		t.Fatal(err)
	}

	if len(resultPolicy.Actions) != 2 {
		t.Fatal("Actions not stored properly")
	}

	if len(resultPolicy.CompiledActions) != 2 {
		t.Fatal("Compiled Actions regular expressions not stored properly")
	}

	if len(resultPolicy.Subjects) != 2 {
		t.Fatal("Subjects not stored properly")
	}

	if len(resultPolicy.CompiledSubjects) != 2 {
		t.Fatal("Compiled Subjects regular expressions not stored properly")
	}

	if len(resultPolicy.Resources) != 2 {
		t.Fatal("Resurces not stored properly")
	}

	if len(resultPolicy.CompiledResources) != 2 {
		t.Fatal("Compiled Resurces regular expressions not stored properly")
	}
}

func TestCreatePolicyWithConditions(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	manager, cleanup, err := NewBackendLadonManager(loadDBConfig())
	if err != nil {
		t.Fatal(err)
	}

	randUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	id := randUUID.String()

	if cleanup != nil {
		defer func() {
			manager.getRepository().DeleteOne(backends.NewFilter().Match("id", id))
			cleanup()
		}()
	}

	authObj := auth.Auth{
		Organizations: []string{"org1", "org2"},
		Roles:         []string{"user"},
		UserID:        "id-1",
		Username:      "username",
	}

	rolesCond, err := NewCondition("RolesCondition", []string{"admin", "writer"})
	if err != nil {
		t.Fatal(err)
	}
	orgCond, err := NewCondition("OrganizationsCondition", []string{"org1", "org2"})
	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read", "api:write"},
		Description: "Description",
		Effect:      ladon.AllowAccess,
		ID:          id,
		Resources:   []string{"/user/<.+>", "/admin"},
		Subjects:    []string{"username", "another-user"},
		Conditions: ladon.Conditions{
			"RolesCondition":         rolesCond,
			"OrganizationsCondition": orgCond,
		},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	record := db.PolicyRecord{}

	if _, err := manager.getRepository().GetOne(backends.NewFilter().Match("id", id), &record); err != nil {
		t.Fatal(err)
	}
	if record.Conditions == "" {
		t.Fatal("Conditions not saved properly")
	}

}

func TestGetPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	manager, cleanup, err := NewBackendLadonManager(loadDBConfig())
	if err != nil {
		t.Fatal(err)
	}

	randUUID, err := uuid.NewV4()
	if err != nil {
		t.Fatal(err)
	}
	id := randUUID.String()

	if cleanup != nil {
		defer func() {
			//manager.Collection.Remove(bson.M{"id": id})
			manager.getRepository().DeleteOne(backends.NewFilter().Match("id", id))
			cleanup()
		}()
	}

	authObj := auth.Auth{
		Organizations: []string{"org1", "org2"},
		Roles:         []string{"user"},
		UserID:        "id-1",
		Username:      "username",
	}

	rolesCond, err := NewCondition("RolesCondition", []string{"admin", "writer"})
	if err != nil {
		t.Fatal(err)
	}
	orgCond, err := NewCondition("OrganizationsCondition", []string{"org1", "org2"})
	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read", "api:write"},
		Description: "Description",
		Effect:      ladon.AllowAccess,
		ID:          id,
		Resources:   []string{"/user/<.+>", "/admin"},
		Subjects:    []string{"username", "another-user"},
		Conditions: ladon.Conditions{
			"RolesCondition":         rolesCond,
			"OrganizationsCondition": orgCond,
		},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	policy, err := manager.Get(id)

	if err != nil {
		t.Fatal(err)
	}

	if policy == nil {
		t.Fatal("Expected to find the policy by Id.")
	}

	if policy.GetActions() == nil || len(policy.GetActions()) != 2 {
		t.Fatal("Actions not saved properly")
	}

	if policy.GetSubjects() == nil || len(policy.GetSubjects()) != 2 {
		t.Fatal("Subjects not saved properly")
	}

	if policy.GetResources() == nil || len(policy.GetResources()) != 2 {
		t.Fatal("Resources not saved properly")
	}

	if policy.GetConditions() == nil {
		t.Fatal("Conditions not deserialized properly")
	}

	if _, ok := policy.GetConditions()["RolesCondition"]; !ok {
		t.Fatal("RolesCondition missing")
	}

	if _, ok := policy.GetConditions()["OrganizationsCondition"]; !ok {
		t.Fatal("OrganizationsCondition missing")
	}
}

func TestFindRequestsCandidates(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	manager, cleanup, err := NewBackendLadonManager(loadDBConfig())
	if err != nil {
		t.Fatal(err)
	}

	ids := []string{}
	for i := 0; i < 4; i++ {

		randUUID, err := uuid.NewV4()
		if err != nil {
			t.Fatal(err)
		}
		id := randUUID.String()
		ids = append(ids, id)
	}

	defer func() {
		for _, id := range ids {
			//manager.Collection.Remove(bson.M{"id": id})
			if e := manager.getRepository().DeleteOne(backends.NewFilter().Match("id", id)); e != nil {
				t.Log("Failed to delete: ", id, " -> ", e.Error())
			}
		}
		if cleanup != nil {
			cleanup()
		}

	}()

	authObj := auth.Auth{
		Organizations: []string{"org1", "org2"},
		Roles:         []string{"user"},
		UserID:        "id-1",
		Username:      "username",
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read", "api:write"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[0],
		Resources:   []string{"/user/<.+>", "/admin"},
		Subjects:    []string{"user1", "user2"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[1],
		Resources:   []string{"/user/<.+>", "/allowed"},
		Subjects:    []string{"user1", "user3"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[2],
		Resources:   []string{"/user/<.+>", "/admin/<.+>/read"},
		Subjects:    []string{"user1", "user4", "user5"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read", "api:write"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[3],
		Resources:   []string{"/user/<.+>", "/admin/<.+>/write"},
		Subjects:    []string{"user1", "user4", "user<.+>"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	// should fetch all policies
	policies, err := manager.FindRequestCandidates(&ladon.Request{
		Action:   "api:read",
		Resource: "/user/1",
		Subject:  "user1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if policies == nil || len(policies) != 4 {
		t.Fatal("Expected to fetch all policies here.")
	}

	policies, err = manager.FindRequestCandidates(&ladon.Request{
		Action:   "api:read",
		Resource: "/allowed",
		Subject:  "user3",
	})

	if err != nil {
		t.Fatal(err)
	}

	if policies == nil || len(policies) != 1 {
		t.Fatal("Expected to fetch just one policy candidate.")
	}

	if policies[0].GetID() != ids[1] {
		t.Fatal("Expected to fetch just the second policy")
	}

	policies, err = manager.FindRequestCandidates(&ladon.Request{
		Action:   "api:read",
		Resource: "/user/some-resource",
		Subject:  "user-12",
	})

	if err != nil {
		t.Fatal(err)
	}

	if policies == nil || len(policies) != 1 {
		t.Fatal("Expected to fetch just one policy candidate.")
	}

	if policies[0].GetID() != ids[3] {
		t.Fatal("Expected to fetch the last policy")
	}

}

func TestFindPoliciesForSubject(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	manager, cleanup, err := NewBackendLadonManager(loadDBConfig())
	if err != nil {
		t.Fatal(err)
	}

	ids := []string{}
	for i := 0; i < 4; i++ {

		randUUID, err := uuid.NewV4()
		if err != nil {
			t.Fatal(err)
		}
		id := randUUID.String()
		ids = append(ids, id)
	}

	if cleanup != nil {
		defer func() {
			for _, id := range ids {
				//manager.Collection.Remove(bson.M{"id": id})
				manager.getRepository().DeleteOne(backends.NewFilter().Match("id", id))
			}
			cleanup()
		}()
	}

	authObj := auth.Auth{
		Organizations: []string{"org1", "org2"},
		Roles:         []string{"user"},
		UserID:        "id-1",
		Username:      "username",
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read", "api:write"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[0],
		Resources:   []string{"/user/<.+>", "/admin"},
		Subjects:    []string{"user1", "user2"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[1],
		Resources:   []string{"/user/<.+>", "/allowed"},
		Subjects:    []string{"user1", "user3"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[2],
		Resources:   []string{"/user/<.+>", "/admin/<.+>/read"},
		Subjects:    []string{"user1", "user4", "user5"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read", "api:write"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[3],
		Resources:   []string{"/user/<.+>", "/admin/<.+>/write"},
		Subjects:    []string{"user1", "user4", "user<.+>"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	policies, err := manager.FindPoliciesForSubject("user1")
	if err != nil {
		t.Fatal(err)
	}

	if policies == nil {
		t.Fatal("Expected to get policies result, but got nil instead")
	}

	if len(policies) != 4 {
		t.Fatalf("Expected to get 4 policies, but got %d instead\n", len(policies))
	}

	policies, err = manager.FindPoliciesForSubject("user2")
	if err != nil {
		t.Fatal(err)
	}

	if policies == nil {
		t.Fatal("Expected to get policies result, but got nil instead")
	}

	if len(policies) != 2 {
		t.Fatalf("Expected to get 2 policy candidates, but got %d instead\n", len(policies))
	}
}

func TestFindPoliciesForResource(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping in short mode")
	}

	manager, cleanup, err := NewBackendLadonManager(loadDBConfig())
	if err != nil {
		t.Fatal(err)
	}

	ids := []string{}
	for i := 0; i < 4; i++ {

		randUUID, err := uuid.NewV4()
		if err != nil {
			t.Fatal(err)
		}
		id := randUUID.String()
		ids = append(ids, id)
	}

	if cleanup != nil {
		defer func() {
			for _, id := range ids {
				//manager.Collection.Remove(bson.M{"id": id})
				manager.getRepository().DeleteAll(backends.NewFilter().Match("id", id))
			}
			cleanup()
		}()
	}

	authObj := auth.Auth{
		Organizations: []string{"org1", "org2"},
		Roles:         []string{"user"},
		UserID:        "id-1",
		Username:      "username",
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read", "api:write"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[0],
		Resources:   []string{"/user/<.+>", "/admin"},
		Subjects:    []string{"user1", "user2"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[1],
		Resources:   []string{"/user/<.+>", "/allowed"},
		Subjects:    []string{"user1", "user3"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[2],
		Resources:   []string{"/user/<.+>", "/admin/<.+>/read"},
		Subjects:    []string{"user1", "user4", "user5"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	err = manager.CreateWithAuth(&ladon.DefaultPolicy{
		Actions:     []string{"api:read", "api:write"},
		Description: "RequestCandidate",
		Effect:      ladon.AllowAccess,
		ID:          ids[3],
		Resources:   []string{"/user/<.+>", "/admin/<.+>/write"},
		Subjects:    []string{"user1", "user4", "user<.+>"},
	}, &authObj)

	if err != nil {
		t.Fatal(err)
	}

	policies, err := manager.FindPoliciesForResource("/user/user-1")
	if err != nil {
		t.Fatal(err)
	}

	if policies == nil {
		t.Fatal("Expected to get policies result, but got nil instead")
	}

	if len(policies) != 4 {
		t.Fatalf("Expected to get 4 policies, but got %d instead\n", len(policies))
	}

	policies, err = manager.FindPoliciesForResource("/admin")
	if err != nil {
		t.Fatal(err)
	}

	if policies == nil {
		t.Fatal("Expected to get policies result, but got nil instead")
	}

	if len(policies) != 1 {
		t.Fatalf("Expected to get 1 policy candidate, but got %d instead\n", len(policies))
	}

	policies, err = manager.FindPoliciesForResource("/admin/sysadmin/write")
	if err != nil {
		t.Fatal(err)
	}

	if policies == nil {
		t.Fatal("Expected to get policies result, but got nil instead")
	}

	if len(policies) != 1 {
		t.Fatalf("Expected to get 1 policy candidate, but got %d instead\n", len(policies))
	}
}
