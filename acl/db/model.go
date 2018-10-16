package db

// PolicyRecord is an ACL policy stored in Mongodb.
type PolicyRecord struct {

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

	// CompiledActions is the compiled regular expression to match the action.
	CompiledActions []string `json:"compiledActions" bson:"compiledActions"`

	// CompiledResources is the compiled regular expression to match the resource.
	CompiledResources []string `json:"compiledResources" bson:"compiledResources"`

	// CompiledSubjects is the compiled regular expression to match the subject.
	CompiledSubjects []string `json:"compiledSubjects" bson:"compiledSubjects"`
}
