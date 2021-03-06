// Code generated by goagen v1.3.0, DO NOT EDIT.
//
// API "acl-manager": Application User Types
//
// Command:
// $ goagen
// --design=github.com/Microkubes/microservice-security/acl/rest
// --out=$(GOPATH)/src/github.com/Microkubes/microservice-security/acl/rest
// --version=v1.2.0-dirty

package app

import (
	"github.com/keitaroinc/goa"
)

// ACL Policy Payload
type aCLPolicyPayload struct {
	// Actions to match the request against.
	Actions []string `form:"actions,omitempty" json:"actions,omitempty" xml:"actions,omitempty"`
	// Custom conditions
	Conditions []*condition `form:"conditions,omitempty" json:"conditions,omitempty" xml:"conditions,omitempty"`
	// Description
	Description *string `form:"description,omitempty" json:"description,omitempty" xml:"description,omitempty"`
	// allow or deny
	Effect *string `form:"effect,omitempty" json:"effect,omitempty" xml:"effect,omitempty"`
	// Policy ID
	ID *string `form:"id,omitempty" json:"id,omitempty" xml:"id,omitempty"`
	// Resources to which this policy applies.
	Resources []string `form:"resources,omitempty" json:"resources,omitempty" xml:"resources,omitempty"`
	// Subjects to match the request against.
	Subjects []string `form:"subjects,omitempty" json:"subjects,omitempty" xml:"subjects,omitempty"`
}

// Validate validates the aCLPolicyPayload type instance.
func (ut *aCLPolicyPayload) Validate() (err error) {
	if ut.Resources == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`request`, "resources"))
	}
	if ut.Effect == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`request`, "effect"))
	}
	if ut.Subjects == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`request`, "subjects"))
	}
	for _, e := range ut.Conditions {
		if e != nil {
			if err2 := e.Validate(); err2 != nil {
				err = goa.MergeErrors(err, err2)
			}
		}
	}
	return
}

// Publicize creates ACLPolicyPayload from aCLPolicyPayload
func (ut *aCLPolicyPayload) Publicize() *ACLPolicyPayload {
	var pub ACLPolicyPayload
	if ut.Actions != nil {
		pub.Actions = ut.Actions
	}
	if ut.Conditions != nil {
		pub.Conditions = make([]*Condition, len(ut.Conditions))
		for i2, elem2 := range ut.Conditions {
			pub.Conditions[i2] = elem2.Publicize()
		}
	}
	if ut.Description != nil {
		pub.Description = ut.Description
	}
	if ut.Effect != nil {
		pub.Effect = *ut.Effect
	}
	if ut.ID != nil {
		pub.ID = ut.ID
	}
	if ut.Resources != nil {
		pub.Resources = ut.Resources
	}
	if ut.Subjects != nil {
		pub.Subjects = ut.Subjects
	}
	return &pub
}

// ACL Policy Payload
type ACLPolicyPayload struct {
	// Actions to match the request against.
	Actions []string `form:"actions,omitempty" json:"actions,omitempty" xml:"actions,omitempty"`
	// Custom conditions
	Conditions []*Condition `form:"conditions,omitempty" json:"conditions,omitempty" xml:"conditions,omitempty"`
	// Description
	Description *string `form:"description,omitempty" json:"description,omitempty" xml:"description,omitempty"`
	// allow or deny
	Effect string `form:"effect" json:"effect" xml:"effect"`
	// Policy ID
	ID *string `form:"id,omitempty" json:"id,omitempty" xml:"id,omitempty"`
	// Resources to which this policy applies.
	Resources []string `form:"resources" json:"resources" xml:"resources"`
	// Subjects to match the request against.
	Subjects []string `form:"subjects" json:"subjects" xml:"subjects"`
}

// Validate validates the ACLPolicyPayload type instance.
func (ut *ACLPolicyPayload) Validate() (err error) {
	if ut.Resources == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`type`, "resources"))
	}
	if ut.Effect == "" {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`type`, "effect"))
	}
	if ut.Subjects == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`type`, "subjects"))
	}
	for _, e := range ut.Conditions {
		if e != nil {
			if err2 := e.Validate(); err2 != nil {
				err = goa.MergeErrors(err, err2)
			}
		}
	}
	return
}

// Payload to allow or deny access to resources.
type accessPolicyPayload struct {
	// Whether to allow access
	Allow *bool `form:"allow,omitempty" json:"allow,omitempty" xml:"allow,omitempty"`
	// Description of the policy
	Description *string `form:"description,omitempty" json:"description,omitempty" xml:"description,omitempty"`
	// Organizations patterns
	Organizations []string `form:"organizations,omitempty" json:"organizations,omitempty" xml:"organizations,omitempty"`
	// Resources patterns
	Resources []string `form:"resources,omitempty" json:"resources,omitempty" xml:"resources,omitempty"`
	// Which roles are allowed
	Roles []string `form:"roles,omitempty" json:"roles,omitempty" xml:"roles,omitempty"`
	// Which scopes are allowed
	Scopes []string `form:"scopes,omitempty" json:"scopes,omitempty" xml:"scopes,omitempty"`
	// Users patterns
	Users []string `form:"users,omitempty" json:"users,omitempty" xml:"users,omitempty"`
}

// Validate validates the accessPolicyPayload type instance.
func (ut *accessPolicyPayload) Validate() (err error) {
	if ut.Resources == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`request`, "resources"))
	}
	if ut.Allow == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`request`, "allow"))
	}
	return
}

// Publicize creates AccessPolicyPayload from accessPolicyPayload
func (ut *accessPolicyPayload) Publicize() *AccessPolicyPayload {
	var pub AccessPolicyPayload
	if ut.Allow != nil {
		pub.Allow = *ut.Allow
	}
	if ut.Description != nil {
		pub.Description = ut.Description
	}
	if ut.Organizations != nil {
		pub.Organizations = ut.Organizations
	}
	if ut.Resources != nil {
		pub.Resources = ut.Resources
	}
	if ut.Roles != nil {
		pub.Roles = ut.Roles
	}
	if ut.Scopes != nil {
		pub.Scopes = ut.Scopes
	}
	if ut.Users != nil {
		pub.Users = ut.Users
	}
	return &pub
}

// Payload to allow or deny access to resources.
type AccessPolicyPayload struct {
	// Whether to allow access
	Allow bool `form:"allow" json:"allow" xml:"allow"`
	// Description of the policy
	Description *string `form:"description,omitempty" json:"description,omitempty" xml:"description,omitempty"`
	// Organizations patterns
	Organizations []string `form:"organizations,omitempty" json:"organizations,omitempty" xml:"organizations,omitempty"`
	// Resources patterns
	Resources []string `form:"resources" json:"resources" xml:"resources"`
	// Which roles are allowed
	Roles []string `form:"roles,omitempty" json:"roles,omitempty" xml:"roles,omitempty"`
	// Which scopes are allowed
	Scopes []string `form:"scopes,omitempty" json:"scopes,omitempty" xml:"scopes,omitempty"`
	// Users patterns
	Users []string `form:"users,omitempty" json:"users,omitempty" xml:"users,omitempty"`
}

// Validate validates the AccessPolicyPayload type instance.
func (ut *AccessPolicyPayload) Validate() (err error) {
	if ut.Resources == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`type`, "resources"))
	}

	return
}

// Custom ACL policy condition
type condition struct {
	// Condition name
	Name *string `form:"name,omitempty" json:"name,omitempty" xml:"name,omitempty"`
	// Patterns to match the value against.
	Patterns []string `form:"patterns,omitempty" json:"patterns,omitempty" xml:"patterns,omitempty"`
	// Condition type.
	Type *string `form:"type,omitempty" json:"type,omitempty" xml:"type,omitempty"`
}

// Validate validates the condition type instance.
func (ut *condition) Validate() (err error) {
	if ut.Name == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`request`, "name"))
	}
	if ut.Type == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`request`, "type"))
	}
	if ut.Patterns == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`request`, "patterns"))
	}
	return
}

// Publicize creates Condition from condition
func (ut *condition) Publicize() *Condition {
	var pub Condition
	if ut.Name != nil {
		pub.Name = *ut.Name
	}
	if ut.Patterns != nil {
		pub.Patterns = ut.Patterns
	}
	if ut.Type != nil {
		pub.Type = *ut.Type
	}
	return &pub
}

// Custom ACL policy condition
type Condition struct {
	// Condition name
	Name string `form:"name" json:"name" xml:"name"`
	// Patterns to match the value against.
	Patterns []string `form:"patterns" json:"patterns" xml:"patterns"`
	// Condition type.
	Type string `form:"type" json:"type" xml:"type"`
}

// Validate validates the Condition type instance.
func (ut *Condition) Validate() (err error) {
	if ut.Name == "" {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`type`, "name"))
	}
	if ut.Type == "" {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`type`, "type"))
	}
	if ut.Patterns == nil {
		err = goa.MergeErrors(err, goa.MissingAttributeError(`type`, "patterns"))
	}
	return
}
