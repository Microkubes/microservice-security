package acl

import (
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
