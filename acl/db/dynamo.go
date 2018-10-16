package db

import (
	"log"
	"regexp"
	"strings"

	"github.com/JormungandrK/backends"
)

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

// ACLSecurityDynamoRepo is Dunamodb based extended implemetation for a backends.Repository.
type ACLSecurityDynamoRepo struct {
	*backends.DynamoCollection
}

// FindPolicies looks up ACL policies from Dynamodb backend database based on filter proprties.
func (a *ACLSecurityDynamoRepo) FindPolicies(filter map[string]string) ([]*PolicyRecord, error) {
	results := []map[string]interface{}{}
	if err := a.DynamoCollection.Table.Scan().All(&results); err != nil {
		return nil, err
	}

	records := []*PolicyRecord{}

	for _, result := range results {
		record := toPolicyRecord(result)
		allMatch := true
		for prop, value := range filter {
			matcher, ok := matchers[prop]
			if ok {
				if !matcher(&record, value) {
					allMatch = false
					break
				}
			}
		}
		if allMatch {
			records = append(records, &record)
		}
	}

	return records, nil
}

func toPolicyRecord(result map[string]interface{}) PolicyRecord {
	record := PolicyRecord{}
	backends.MapToInterface(result, &record)
	return record
}

// ACLSecurityDynamoRepoExtender extends the given backends.Repository as ACLRepository.
func ACLSecurityDynamoRepoExtender(repo backends.Repository) backends.Repository {
	dynamoCollection, ok := repo.(*backends.DynamoCollection)
	if !ok {
		log.Println("WARN: Thr repository cannot be extended because is not of type '*backends.DynamoCollection'.")
		return repo
	}
	return &ACLSecurityDynamoRepo{
		DynamoCollection: dynamoCollection,
	}
}
