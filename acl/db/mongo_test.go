package db

import (
	"testing"

	"github.com/JormungandrK/backends"
)

func TestTypeConversion(t *testing.T) {
	aclMongo := &ACLSecurityMongoRepo{}

	var repo interface{}

	repo = aclMongo

	if _, ok := repo.(ACLRepository); !ok {
		t.Fatal("Cannot convert to ACLRepository.")
	}
	if _, ok := repo.(backends.Repository); !ok {
		t.Fatal("Cannot convert to backends.Repository")
	}

	bRepo := repo.(backends.Repository)

	if _, ok := bRepo.(ACLRepository); !ok {
		t.Fatal("Failed to cast backends.Repository -> ACLRepository ")
	}

}
