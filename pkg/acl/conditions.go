package acl

import (
	"fmt"
	"regexp"

	"github.com/ory/ladon"
)

type AllowedPatternsCondition struct {
	Name   string
	Values []string
}

func (cond *AllowedPatternsCondition) GetName() string {
	return cond.Name
}

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
	for _, ap := range patterns {
		matches, err := regexp.MatchString(ap, strVal)
		if err != nil {
			return false
		}
		if matches {
			return true
		}
	}
	return false
}

// NewCondition creates a new AllowedPatternsCondition with the given name and list of allowed patterns.
// This function checks if there is a condition factory registered with the requested name. If there isn't one,
// an error is returned - as the condition could not be deserialized when fetched from the persistence.
func NewCondition(name string, patterns []string) (ladon.Condition, error) {
	if _, ok := ladon.ConditionFactories[name]; !ok {
		return nil, fmt.Errorf("no condition with name %s registered", name)
	}

	cond := &AllowedPatternsCondition{
		Name:   name,
		Values: patterns,
	}
	return cond, nil
}
