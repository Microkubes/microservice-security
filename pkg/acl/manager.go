package acl

import (
	"fmt"
	"time"

	"github.com/Microkubes/backends"
	"github.com/Microkubes/microservice-security/acl/db"
	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-tools/config"
	"github.com/ory/ladon"
	"github.com/ory/ladon/compiler"
	uuid "github.com/satori/go.uuid"
)

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
	conditions, err := policy.GetConditions().MarshalJSON()
	if err != nil {
		return nil, err
	}
	mpr.Conditions = string(conditions)
	return &mpr, nil
}

func getCompiledRegex(values []string, startDelimiter byte, endDelimiter byte) (compiled []string, err error) {
	for _, val := range values {
		compValue, err := compiler.CompileRegex(val, startDelimiter, endDelimiter)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, compValue.String())
	}
	return compiled, nil
}

func toLadonPolicy(mpr *db.PolicyRecord) (ladon.Policy, error) {
	conditions := ladon.Conditions{}
	err := conditions.UnmarshalJSON([]byte(mpr.Conditions))
	if err != nil {
		return nil, err
	}
	return &ladon.DefaultPolicy{
		Actions:     mpr.Actions,
		Description: mpr.Description,
		Effect:      mpr.Effect,
		ID:          mpr.ID,
		Resources:   mpr.Resources,
		Subjects:    mpr.Subjects,
		Conditions:  conditions,
	}, nil
}

func toLadonPolicies(policies []*db.PolicyRecord) (policyRecords ladon.Policies, err error) {
	for _, pol := range policies {
		policy, err := toLadonPolicy(pol)
		if err != nil {
			return nil, err
		}
		policyRecords = append(policyRecords, policy)
	}
	return policyRecords, nil
}

// Create persists the policy to db
func (m *BackendLadonManager) Create(policy ladon.Policy) error {
	return fmt.Errorf("use CreateWithAuth instead")
}

// CreateWithAuth persists the policy. It also sets the "createdBy" property to the provided authentication.
func (m *BackendLadonManager) CreateWithAuth(policy ladon.Policy, a *auth.Auth) error {
	if a == nil || a.UserID == "" {
		return fmt.Errorf("no auth object or user id provided")
	}
	record, err := toMongoRecord(policy)
	if err != nil {
		return err
	}
	record.CreatedAt = time.Now().Unix()
	if record.ID == "" {
		randid, err := uuid.NewV4()
		if err != nil {
			return err
		}
		record.ID = randid.String()
	}

	record.CreatedBy = a.UserID
	repo, err := m.getRepository()
	if err != nil {
		return err
	}
	_, err = repo.Save(record, nil)

	return err
}

// Update updates the existing policy.
func (m *BackendLadonManager) Update(policy ladon.Policy) error {
	record, err := toMongoRecord(policy)
	if err != nil {
		return err
	}

	repo, err := m.getRepository()
	if err != nil {
		return err
	}
	res, err := repo.GetOne(backends.NewFilter().Match("id", policy.GetID()), &db.PolicyRecord{})
	if err != nil {
		return err
	}
	existing := res.(*db.PolicyRecord)
	if existing.CreatedAt != 0 {
		record.CreatedAt = existing.CreatedAt
	}
	if existing.CreatedBy != "" {
		record.CreatedBy = existing.CreatedBy
	}

	_, err = repo.Save(record, backends.NewFilter().Match("id", record.ID))
	return err
}

// Get retrieves a single policy.
func (m *BackendLadonManager) Get(id string) (ladon.Policy, error) {
	repo, err := m.getRepository()
	if err != nil {
		return nil, err
	}
	res, err := repo.GetOne(backends.NewFilter().Match("id", id), &db.PolicyRecord{})
	if err != nil {
		return nil, err
	}
	return toLadonPolicy(res.(*db.PolicyRecord))
}

// Delete removes a single policy from the database.
func (m *BackendLadonManager) Delete(id string) error {
	repo, err := m.getRepository()
	if err != nil {
		return err
	}
	err = repo.DeleteAll(backends.NewFilter().Match("id", id))
	return err
}

// GetAll retrieves all policies from the database.
func (m *BackendLadonManager) GetAll(limit, offset int64) (ladon.Policies, error) {
	policies := ladon.Policies{}
	repo, err := m.getRepository()
	if err != nil {
		return nil, err
	}
	res, err := repo.GetAll(nil, &db.PolicyRecord{}, "createdOn", "desc", int(limit), int(offset))
	if err != nil {
		return nil, err
	}
	records, ok := res.([]*db.PolicyRecord)
	if !ok {
		return nil, fmt.Errorf("type conversion failed - result is not []*db.PolicyRecord")
	}
	for _, mpr := range records {
		mpr := mpr
		policy, err := toLadonPolicy(mpr)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	return policies, nil
}

// FindRequestCandidates returns candidates that could match the request object. It either returns
// a set that exactly matches the request, or a superset of it. If an error occurs, it returns nil and
// the error.
func (m *BackendLadonManager) FindRequestCandidates(r *ladon.Request) (ladon.Policies, error) {
	repo, err := m.getACLRepository()
	if err != nil {
		return nil, err
	}
	results, err := repo.FindPolicies(map[string]string{
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
	repo, err := m.getACLRepository()
	if err != nil {
		return nil, err
	}
	results, err := repo.FindPolicies(map[string]string{
		"subject": subject,
	})
	if err != nil {
		return nil, err
	}
	return toLadonPolicies(results)
}

// FindPoliciesForResource retrieves all ladon.Policy candidates that can handle a request for a given resource.
func (m *BackendLadonManager) FindPoliciesForResource(resource string) (ladon.Policies, error) {
	repo, err := m.getACLRepository()
	if err != nil {
		return nil, err
	}

	results, err := repo.FindPolicies(map[string]string{
		"resource": resource,
	})
	if err != nil {
		return nil, err
	}
	return toLadonPolicies(results)
}

func (m *BackendLadonManager) getRepository() (backends.Repository, error) {
	beType := m.backendTypeProvider()
	be, err := m.backendManager.GetBackend(beType)
	if err != nil {
		return nil, err
	}
	repo, err := be.GetRepository("ACL")
	if err != nil {
		return nil, err
	}
	return repo, nil
}

func (m *BackendLadonManager) getACLRepository() (db.ACLRepository, error) {
	repo, err := m.getRepository()
	if err != nil {
		return nil, err
	}
	return repo.(db.ACLRepository), nil
}

// NewBackendLadonManager returns a BackendLadonManager for the given db configuration
func NewBackendLadonManager(cfg *config.DBConfig) (*BackendLadonManager, func(), error) {
	manager := backends.NewBackendSupport(map[string]*config.DBInfo{
		cfg.DBName: &cfg.DBInfo,
	})
	manager = db.WrapBackendManager(manager, map[string]db.RepoExtender{
		"mongodb":  db.ACLSecurityMongoRepoExtender,
		"dynamodb": db.ACLSecurityDynamoRepoExtender,
	})

	noop := func() {}

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
