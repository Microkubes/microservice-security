package db

import (
	"log"

	"github.com/JormungandrK/backends"
	"gopkg.in/mgo.v2/bson"
)

type ACLSecurityMongoRepo struct {
	*backends.MongoCollection
	compiledQueries map[string]func(val string) string
}

func (a *ACLSecurityMongoRepo) FindPolicies(filter map[string]string) ([]*PolicyRecord, error) {
	results := []PolicyRecord{}

	var mongoFilter bson.M

	if filter == nil || len(filter) == 0 {
		mongoFilter = nil
	} else if len(filter) == 1 {
		for prop, value := range filter {
			query, ok := a.compiledQueries[prop]
			if !ok {
				return nil, backends.ErrInvalidInput("find policies by '%s' not supported", prop)
			}
			mongoFilter = bson.M{
				"$where": query(value),
			}
		}

	} else {
		filters := []bson.M{}
		for prop, value := range filter {
			query, ok := a.compiledQueries[prop]
			if !ok {
				return nil, backends.ErrInvalidInput("find policies by '%s' not supported", prop)
			}
			bsonFilter := bson.M{
				"$where": query(value),
			}
			filters = append(filters, bsonFilter)
		}
		mongoFilter = bson.M{
			"$and": filters,
		}
	}

	err := a.MongoCollection.Find(mongoFilter).All(&results)

	if err != nil {
		return nil, err
	}
	policyRecords := []*PolicyRecord{}
	for _, record := range results {
		policyRecords = append(policyRecords, &record)
	}
	return policyRecords, nil
}

func ACLSecurityMongoRepoExtender(repo backends.Repository) backends.Repository {
	mongoCollection, ok := repo.(*backends.MongoCollection)
	if !ok {
		log.Println("WARN: The incoming repository cannot be wrapped to an ACL Mongo repository because it is not of type *backends.MongoCollection.")
		return repo
	}
	return &ACLSecurityMongoRepo{
		MongoCollection: mongoCollection,
	}
}
