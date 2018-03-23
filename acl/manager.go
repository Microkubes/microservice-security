package acl

import (
	"fmt"
	"time"

	"github.com/Microkubes/microservice-security/auth"
	"github.com/Microkubes/microservice-tools/config"
	"github.com/ory/ladon"
	"github.com/ory/ladon/compiler"
	uuid "github.com/satori/go.uuid"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// MongoPolicyRecord is an ACL policy stored in Mongodb.
type MongoPolicyRecord struct {

	// The ID of the policy document
	ID string `json:"id" bson:"id"`

	// Description is the human readable description of the document.
	Description string `json:"description" bson:"description"`

	// List of subjects (may be patterns) to which this policy applies.
	Subjects []string `json:"subjects" bson:"subjects"`

	// Effect is the effect of this policy if applied to the requested resource. May be "allow" or "deny".
	Effect string `json:"effect" bson:"effect"`

	// Resources is a list of resources (may be patterns) to which this policy applies.
	Resources []string `json:"resources" bson:"resources"`

	// Actions is a list of actions (may be patterns) to which this policy applies.
	Actions []string `json:"actions" bson:"actions"`

	// CreatedAt is a timestamp of when this policy was created.
	CreatedAt int64 `json:"createdAt" bson:"createdAt"`

	// Conditions holds the conditions serialized as JSON string.
	Conditions string `json:"conditions" bson:"conditions"`

	// CreatedBy is the user id of the user who created this policy
	CreatedBy string `json:"createdBy" bson:"createdBy"`

	CompiledActions   []string `json:"compiledActions" bson:"compiledActions"`
	CompiledResources []string `json:"compiledResources" bson:"compiledResources"`
	CompiledSubjects  []string `json:"compiledSubjects" bson:"compiledSubjects"`
}

// MongoDBLadonManager holds the mongo collection for storing the ladon policies
// in a Mongodb backend.
type MongoDBLadonManager struct {
	*mgo.Collection
}

func toMongoRecord(policy ladon.Policy) (*MongoPolicyRecord, error) {
	mpr := MongoPolicyRecord{
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

func toLadonPolicy(mpr *MongoPolicyRecord) (ladon.Policy, error) {
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

// Create persists the policy.
func (m *MongoDBLadonManager) Create(policy ladon.Policy) error {
	return fmt.Errorf("use MongoDBLadonManager.CreateWithAuth instead")
}

// CreateWithAuth persists the policy. It also sets the "createdBy" property to the provided authentication.
func (m *MongoDBLadonManager) CreateWithAuth(policy ladon.Policy, authObj *auth.Auth) error {
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

	return m.Collection.Insert(record)
}

// Update updates an existing policy.
func (m *MongoDBLadonManager) Update(policy ladon.Policy) error {
	record, err := toMongoRecord(policy)
	if err != nil {
		return err
	}
	found := map[string]interface{}{}
	err = m.Collection.Find(bson.M{
		"id": policy.GetID(),
	}).One(found)
	if err != nil {
		return err
	}
	if _, ok := found["id"]; !ok {
		return fmt.Errorf("not-found")
	}
	if cb, ok := found["createdBy"]; ok {
		record.CreatedBy = cb.(string)
	}
	if ca, ok := found["createdAt"]; ok {
		record.CreatedAt = ca.(int64)
	}

	return m.Collection.UpdateId(found["_id"], record)
}

// Get retrieves a policy.
func (m *MongoDBLadonManager) Get(id string) (ladon.Policy, error) {
	mpr := MongoPolicyRecord{}
	err := m.Collection.Find(bson.M{
		"id": id,
	}).One(&mpr)

	if err != nil {
		if err.Error() == "not found" {
			return nil, nil
		}
		return nil, err
	}

	if mpr.ID == "" {
		return nil, nil
	}

	return toLadonPolicy(&mpr)
}

// Delete removes a policy.
func (m *MongoDBLadonManager) Delete(id string) error {
	return m.Collection.Remove(bson.M{
		"id": id,
	})
}

// GetAll retrieves all policies.
func (m *MongoDBLadonManager) GetAll(limit, offset int64) (ladon.Policies, error) {
	policies := ladon.Policies{}
	records := []MongoPolicyRecord{}
	err := m.Collection.Find(bson.M{}).Skip(int(offset)).Limit(int(limit)).All(&records)

	if err != nil {
		return nil, err
	}
	for _, mpr := range records {
		policy, e := toLadonPolicy(&mpr)
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
func (m *MongoDBLadonManager) FindRequestCandidates(r *ladon.Request) (ladon.Policies, error) {

	// Multiple filters here:
	// Step 1 - match Resource by regex in mongo, AND
	// step 2 - match subjects by regex in mongo (array), AND
	// step 3 - match actions by regex in mongo
	results := []MongoPolicyRecord{}
	err := m.Collection.Find(bson.M{
		"$and": []bson.M{
			bson.M{
				"$where": fmt.Sprintf("this.compiledResources.filter(function(rc){ return RegExp(rc).test('%s'); }).length > 0", r.Resource),
			},
			bson.M{
				"$where": fmt.Sprintf("this.compiledSubjects.filter(function(sub){ return RegExp(sub).test('%s'); }).length > 0", r.Subject),
			},
			bson.M{
				"$where": fmt.Sprintf("this.compiledActions.filter(function(act){ return RegExp(act).test('%s'); }).length > 0", r.Action),
			},
		},
	}).All(&results)

	if err != nil {
		return nil, err
	}

	policies := []ladon.Policy{}

	for _, record := range results {
		policy, err := toLadonPolicy(&record)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	// return all results back
	return policies, nil
}

// NewMongoDBLadonManager builds a MongoDBLadonManager for the given database configuration.
func NewMongoDBLadonManager(config *config.DBConfig) (*MongoDBLadonManager, func(), error) {
	session, err := mgo.DialWithInfo(&mgo.DialInfo{
		Addrs:    []string{config.Host},
		Username: config.Username,
		Password: config.Password,
		Database: config.DatabaseName,
		Timeout:  30 * time.Second,
	})
	if err != nil {
		return nil, nil, err
	}
	// SetMode - consistency mode for the session.
	session.SetMode(mgo.Monotonic, true)

	collection := session.DB(config.DatabaseName).C("ACL")

	err = collection.EnsureIndex(mgo.Index{
		Background: true,
		Key:        []string{"id"},
		DropDups:   true,
		Unique:     true,
	})

	if err != nil {
		return nil, nil, err
	}

	return &MongoDBLadonManager{
			Collection: collection,
		}, func() {
			session.Close()
		}, nil
}
