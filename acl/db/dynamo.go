package db

import (
	"log"

	"github.com/JormungandrK/backends"
)

type ACLSecurityDynamoRepo struct {
	*backends.DynamoCollection
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
