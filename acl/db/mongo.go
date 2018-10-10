package db

import (
	"log"

	"github.com/JormungandrK/backends"
)

type ACLSecurityMongoRepo struct {
	*backends.MongoCollection
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
