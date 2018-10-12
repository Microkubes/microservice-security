package db

import (
	"log"
	"regexp"
	"strings"

	"github.com/JormungandrK/backends"
)

const DEBUG = true

const CacheSize = 128 // Keep the latest 128 policies in LRU cache.

var matchers = map[string]func(*PolicyRecord, string) bool{
	"subject": func(record *PolicyRecord, value string) bool {
		return matchAnySafe(record.CompiledSubjects, value)
	},
	"resource": func(record *PolicyRecord, value string) bool {
		return matchAnySafe(record.CompiledResources, value)
	},
	"action": func(record *PolicyRecord, value string) bool {
		return matchAnySafe(record.CompiledActions, value)
	},
}

func matchAny(patterns []string, value string) (bool, error) {
	for _, pattern := range patterns {
		match, err := regexp.MatchString(pattern, value)
		if err != nil {
			return false, err
		}
		if match {
			return true, nil
		}
	}
	return false, nil
}

func matchAnySafe(patterns []string, value string) bool {
	if patterns == nil {
		return false
	}
	matched, err := matchAny(patterns, value)
	if err != nil {
		log.Printf("ERROR: error while matching %s against patterns [%s]: %s\n", value, strings.Join(patterns, ", "), err.Error())
		return false
	}
	return matched
}

type ACLSecurityDynamoRepo struct {
	*backends.DynamoCollection
}

func (a *ACLSecurityDynamoRepo) FindPolicies(filter map[string]string) ([]*PolicyRecord, error) {
	results := []PolicyRecord{}
	if err := a.DynamoCollection.Table.Scan().All(&results); err != nil {
		return nil, err
	}

	records := []*PolicyRecord{}

	for _, record := range results {
		anyMatch := false
		for prop, value := range filter {
			matcher, ok := matchers[prop]
			if ok {
				anyMatch = matcher(&record, value)
				if anyMatch {
					break
				}
			}
		}
		if anyMatch {
			records = append(records, &record)
		}
	}

	return records, nil
}

func ACLSecurityDynamoRepoExtender(repo backends.Repository) backends.Repository {
	dynamoCollection, ok := repo.(*backends.DynamoCollection)
	if !ok {
		log.Printf("WARN: ne.\n")
		return repo
	}
	return &ACLSecurityDynamoRepo{
		DynamoCollection: dynamoCollection,
	}
}
