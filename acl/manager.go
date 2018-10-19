package acl

import (
	"fmt"
	"log"
	"time"

	"github.com/JormungandrK/backends"

	"github.com/Microkubes/microservice-security/acl/db"
	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-tools/config"
	"github.com/ory/ladon"
	"github.com/ory/ladon/compiler"
	uuid "github.com/satori/go.uuid"
)

// BackendLadonManager holds the mongo collection for storing the ladon policies
// in a Mongodb backend.
type BackendLadonManager struct {
	backendManager      backends.BackendManager
	backendTypeProvider func() string
}

func toMongoRecord(policy ladon.Policy) (*db.PolicyRecord, error) {
	mpr := db.PolicyRecord{
		ID:          policy.GetID(),
		Description: policy.GetDescription(),
		Actions:     policy.GetActions(),
		Effect:      policy.GetEffect(),
		Resources:   policy.GetResources(),
		Subjects:    policy.GetSubjects(),
	}

	var err error
	mpr.CompiledActions, err = getCompiledRegex(mpr.Actions, policy.GetStartDelimiter(), policy.GetEndDelimiter())
	if err != nil {
		return nil, err
	}

	mpr.CompiledResources, err = getCompiledRegex(mpr.Resources, policy.GetStartDelimiter(), policy.GetEndDelimiter())
	if err != nil {
		return nil, err
	}
	mpr.CompiledSubjects, err = getCompiledRegex(mpr.Subjects, policy.GetStartDelimiter(), policy.GetEndDelimiter())
	if err != nil {
		return nil, err
	}

	condJSON, err := policy.GetConditions().MarshalJSON()
	if err != nil {
		return nil, err
	}
	mpr.Conditions = string(condJSON)
	return &mpr, nil
}

func getCompiledRegex(values []string, startDelimiter byte, endDelimiter byte) ([]string, error) {
	compiled := []string{}

	for _, value := range values {
		compValue, err := compiler.CompileRegex(value, startDelimiter, endDelimiter)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, compValue.String())
	}
	return compiled, nil
}

func toLadonPolicy(mpr *db.PolicyRecord) (ladon.Policy, error) {
	defPolicy := ladon.DefaultPolicy{
		Actions:     mpr.Actions,
		Description: mpr.Description,
		Effect:      mpr.Effect,
		ID:          mpr.ID,
		Resources:   mpr.Resources,
		Subjects:    mpr.Subjects,
	}

	conditions := ladon.Conditions{}

	err := conditions.UnmarshalJSON([]byte(mpr.Conditions))
	if err != nil {
		return nil, err
	}

	defPolicy.Conditions = conditions

	return &defPolicy, nil
}

func toLadonPolicies(policyRecords []*db.PolicyRecord) (ladon.Policies, error) {
	policies := []ladon.Policy{}

	for _, record := range policyRecords {
		policy, err := toLadonPolicy(record)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	// return all policies back
	return policies, nil
}

// Create persists the policy.
func (m *BackendLadonManager) Create(policy ladon.Policy) error {
	return fmt.Errorf("use BackendLadonManager.CreateWithAuth instead")
}

// CreateWithAuth persists the policy. It also sets the "createdBy" property to the provided authentication.
func (m *BackendLadonManager) CreateWithAuth(policy ladon.Policy, authObj *auth.Auth) error {
	if authObj == nil || authObj.UserID == "" {
		return fmt.Errorf("no auth provided")
	}
	record, err := toMongoRecord(policy)
	if err != nil {
		return err
	}
	record.CreatedAt = time.Now().Unix()
	if record.ID == "" {
		randUUID, err := uuid.NewV4()
		if err != nil {
			return err
		}
		record.ID = randUUID.String()
	}

	record.CreatedBy = authObj.UserID

	_, err = m.getRepository().Save(record, nil)

	return err
}

// Update updates an existing policy.
func (m *BackendLadonManager) Update(policy ladon.Policy) error {
	record, err := toMongoRecord(policy)
	if err != nil {
		return err
	}

	res, err := m.getRepository().GetOne(backends.NewFilter().Match("id", policy.GetID()), &db.PolicyRecord{})
	if err != nil {
		if backends.IsErrNotFound(err) {
			return fmt.Errorf("not-found")
		}
		return err
	}
	exsting := res.(*db.PolicyRecord)
	if exsting.CreatedAt != 0 {
		record.CreatedAt = exsting.CreatedAt
	}
	if exsting.CreatedBy != "" {
		record.CreatedBy = exsting.CreatedBy
	}

	_, err = m.getRepository().Save(record, backends.NewFilter().Match("id", record.ID))
	return err
}

// Get retrieves a policy.
func (m *BackendLadonManager) Get(id string) (ladon.Policy, error) {
	res, err := m.getRepository().GetOne(backends.NewFilter().Match("id", id), &db.PolicyRecord{})
	if err != nil {
		if backends.IsErrNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	return toLadonPolicy(res.(*db.PolicyRecord))
}

// Delete removes a policy.
func (m *BackendLadonManager) Delete(id string) error {
	return m.getRepository().DeleteAll(backends.NewFilter().Match("id", id))
}

// GetAll retrieves all policies.
func (m *BackendLadonManager) GetAll(limit, offset int64) (ladon.Policies, error) {
	policies := ladon.Policies{}
	result, err := m.getRepository().GetAll(nil, &db.PolicyRecord{}, "createdOn", "desc", int(limit), int(offset))
	if err != nil {
		return nil, err
	}

	records, ok := result.([]*db.PolicyRecord)
	if !ok {
		return nil, fmt.Errorf("type conversion failed - result is not []*db.PolicyRecord")
	}

	for _, mpr := range records {
		policy, e := toLadonPolicy(mpr)
		if e != nil {
			return nil, e
		}
		policies = append(policies, policy)
	}

	return policies, nil
}

// FindRequestCandidates returns candidates that could match the request object. It either returns
// a set that exactly matches the request, or a superset of it. If an error occurs, it returns nil and
// the error.
func (m *BackendLadonManager) FindRequestCandidates(r *ladon.Request) (ladon.Policies, error) {
	results, err := m.getACLRepository().FindPolicies(map[string]string{
		"resource": r.Resource,
		"subject":  r.Subject,
		"action":   r.Action,
	})
	if err != nil {
		return nil, err
	}

	return toLadonPolicies(results)
}

// FindPoliciesForSubject retrieves all ladon.Policy candidates that can handle a request for a given subject.
func (m *BackendLadonManager) FindPoliciesForSubject(subject string) (ladon.Policies, error) {
	results, err := m.getACLRepository().FindPolicies(map[string]string{
		"subject": subject,
	})

	if err != nil {
		return nil, err
	}

	return toLadonPolicies(results)
}

// FindPoliciesForResource retrieves all ladon.Policy candidates that can handle a request for a given resource.
func (m *BackendLadonManager) FindPoliciesForResource(resource string) (ladon.Policies, error) {
	results, err := m.getACLRepository().FindPolicies(map[string]string{
		"resource": resource,
	})

	if err != nil {
		return nil, err
	}

	return toLadonPolicies(results)
}

func (m *BackendLadonManager) getRepository() backends.Repository {
	backendType := m.backendTypeProvider()
	backend, err := m.backendManager.GetBackend(m.backendTypeProvider())
	if err != nil {
		log.Fatalf("Failed to get backend of type '%s': %s\n", backendType, err.Error())
	}
	repository, err := backend.GetRepository("ACL")
	if err != nil {
		log.Fatal("Failed to setup ACL repository: ", err.Error())
	}
	return repository
}

func (m *BackendLadonManager) getACLRepository() db.ACLRepository {
	repo := m.getRepository()
	aclRepo, ok := repo.(db.ACLRepository)
	if !ok {
		log.Fatal("The underlying backend does not support ACL extended repository actions.")
	}
	return aclRepo
}

// NewBackendLadonManager builds a BackendLadonManager for the given database configuration.
func NewBackendLadonManager(cfg *config.DBConfig) (*BackendLadonManager, func(), error) {
	manager := backends.NewBackendSupport(map[string]*config.DBInfo{
		cfg.DBName: &cfg.DBInfo,
	})
	manager = db.WrapBackendManager(manager, map[string]db.RepoExtender{
		"mongodb":  db.ACLSecurityMongoRepoExtender,
		"dynamodb": db.ACLSecurityDynamoRepoExtender,
	})

	noop := func() {}

	// let's define the repositories

	backend, err := manager.GetBackend(cfg.DBName)
	if err != nil {
		return nil, noop, err
	}

	if _, err = backend.DefineRepository("ACL", backends.RepositoryDefinitionMap{
		"customId":      true, // we generate our own IDs
		"name":          "ACL",
		"enableTtl":     false,
		"hashKey":       "id",
		"rangeKey":      "createdAt",
		"rangeKeyType":  "N",
		"readCapacity":  50,
		"writeCapacity": 50,
		"indexes": []backends.Index{
			backends.NewUniqueIndex("id"),
			backends.NewNonUniqueIndex("createdAt"),
		},
	}); err != nil {
		return nil, noop, err
	}

	return &BackendLadonManager{
		backendManager: manager,
		backendTypeProvider: func() string {
			return cfg.DBName
		},
	}, noop, nil
}
