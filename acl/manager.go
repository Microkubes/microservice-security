package acl

import (
	"fmt"
	"time"

	"github.com/ory/ladon"
	uuid "github.com/satori/go.uuid"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type MongoPolicyRecord struct {
	ID          string   `json:"id" bson:"id"`
	Description string   `json:"description" bson:"description"`
	Subjects    []string `json:"subjects" bson:"subjects"`
	Effect      string   `json:"effect" bson:"effect"`
	Resources   []string `json:"resources" bson:"resources"`
	Actions     []string `json:"actions" bson:"actions"`
	CreatedAt   int64    `json:"createdAt" bson:"createdAt"`
	Conditions  string   `json:"conditions" bson:"conditions"`
}

type MongoDBLadonManager struct {
	mgo.Collection
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

	condJSON, err := policy.GetConditions().MarshalJSON()
	if err != nil {
		return nil, err
	}
	mpr.Conditions = string(condJSON)
	return &mpr, nil
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
	record, err := toMongoRecord(policy)
	if err != nil {
		return err
	}
	record.CreatedAt = time.Now().Unix()
	if record.ID == "" {
		record.ID = uuid.NewV4().String()
	}
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
	return m.Collection.UpdateId(found["id"], record)
}

// Get retrieves a policy.
func (m *MongoDBLadonManager) Get(id string) (ladon.Policy, error) {
	mpr := MongoPolicyRecord{}
	err := m.Collection.Find(bson.M{
		"id": id,
	}).One(&mpr)

	if err != nil {
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
		"$or": []bson.M{
			bson.M{
				"$where": fmt.Sprintf("this.resources.filter(function(rc){ return RegExp(rc).test('%s'); }).length > 0", r.Resource),
			},
			bson.M{
				"$where": fmt.Sprintf("this.subjects.filter(function(sub){ return RegExp(sub).test('%s'); }).length > 0", r.Subject),
			},
			bson.M{
				"$where": fmt.Sprintf("this.actions.filter(function(act){ return RegExp(act).test('%s'); }).length > 0", r.Action),
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
