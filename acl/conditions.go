package acl

import (
	"fmt"
	"regexp"

	"github.com/ory/ladon"
)

// AllowedPatternsCondition is a custom condition that matches the value of a
// custom ladon.Context property against a list of allowed regular expression patterns.
// If any of the regex patterns matches the value, the condition is fulfilled.
// If the value in the ACL Context (ladon.Context) is nil or not a string, the
// condition returns false (is NOT fulfilled).
type AllowedPatternsCondition struct {
	// Name is the name of the condition. The condition will be registerd with Ladon under this name.
	Name string

	// List of regex values for this condition. The context value is matched against all of these regex patterns to find a match.
	Values []string
}

// GetName returns the name of the condition. Used for condition registration and building.
func (cond *AllowedPatternsCondition) GetName() string {
	return cond.Name
}

// Fulfills checks if the value provided as argument and the ladon.Request fullfill this Condition.
// The value is checked against the list of patterns in the condition. If the value mathes any of the
// condition patterns, the condition is fulfilled.
func (cond *AllowedPatternsCondition) Fulfills(value interface{}, r *ladon.Request) bool {
	if value == nil {
		return false
	}

	strVal, ok := value.(string)
	if !ok {
		return false
	}

	for _, allowedPattern := range cond.Values {
		matches, err := regexp.MatchString(allowedPattern, strVal)
		if err != nil {
			return false
		}
		if matches {
			return true
		}
	}

	return false
}

type OwnerCondition struct {
}

func (o *OwnerCondition) GetName() string {
	return "OwnerCondition"
}

func (o *OwnerCondition) Fulfills(value interface{}, req *ladon.Request) bool {
	if value == nil {
		// Don't match owner if not set in the request.
		return true
	}
	return value == req.Subject
}

// AvailableConditions is the list of names of the available AllowedPatternsCondition conditions.
// All of these are registered with ladon.
var AvailableConditions = []string{"RolesCondition", "ScopesCondition", "OrganizationsCondition"}

func init() {
	// Register custom conditions
	for _, condName := range AvailableConditions {
		ladon.ConditionFactories[condName] = func() ladon.Condition {
			return &AllowedPatternsCondition{
				Name: condName,
			}
		}
	}
	ladon.ConditionFactories["OwnerCondition"] = func() ladon.Condition {
		return &OwnerCondition{}
	}
}

// NewCondition creates a new AllowedPatternsCondition with the given name and list of allowed patterns.
// This function checks if there is a condition factory registered with the requested name. If there isn't one,
// an error is returned - as the condition could not be deserialized when fetched from the persistence.
func NewCondition(name string, patterns []string) (ladon.Condition, error) {
	if _, ok := ladon.ConditionFactories[name]; !ok {
		return nil, fmt.Errorf("No condition with name %s registered", name)
	}

	cond := &AllowedPatternsCondition{
		Name:   name,
		Values: patterns,
	}
	return cond, nil
}
