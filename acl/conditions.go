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
	if ok {
		return matchPatterns(strVal, cond.Values)
	}

	strValues, ok := value.([]string)
	if ok {
		for _, strVal := range strValues {
			if matchPatterns(strVal, cond.Values) {
				return true
			}
		}
	}

	return false
}

func matchPatterns(strVal string, patterns []string) bool {
	for _, allowedPattern := range patterns {
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

// OwnerCondition is used to implement a special kind of condition for
// checking the owner of a resource.
type OwnerCondition struct {
}

// GetName returns the name of the condition - "OwnerCondition"
func (o *OwnerCondition) GetName() string {
	return "OwnerCondition"
}

// Fulfills checks if the request context contains an owner. If so, it checks if
// the subject has the same value as the owner.
// If no owner values is set, then the request is allowed.
// The value of the owner is retrieved from the request context based on the name of the condition.
// When setting the condition in a policy, it is associated with a name, for example:
//   cond := &ladon.DefaultPolicy{
//     conditions: ladon.Conditions{
//       "createdBy": &OwnerCondition{},
//     },
//   }
// In this example, the owner value is extracted from the property "createdBy"
// of the request context.
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
		conditionName := condName
		ladon.ConditionFactories[condName] = func() ladon.Condition {
			return &AllowedPatternsCondition{
				Name: conditionName,
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
