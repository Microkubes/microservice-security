package db

import (
	"testing"

	"github.com/Microkubes/backends"
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

func TestGenerateReverseRegexpMatch(t *testing.T) {
	expression := reverseRegexpMatch("prop1", "/value")
	if expression == "" {
		t.Fatal("Expected expression instead of empty string.")
	}
	if expression != "this.prop1.filter(function(rc){ return RegExp(rc).test('/value'); }).length > 0" {
		t.Fatal("Invalid expression.")
	}
}

func TestACLSecurityMongoRepoExtender(t *testing.T) {
	origRepo := &backends.MongoCollection{}

	extended := ACLSecurityMongoRepoExtender(origRepo)

	if extended == nil {
		t.Fatal("Expected an extended backends.Repository instead of nil.")
	}

	if _, ok := extended.(*ACLSecurityMongoRepo); !ok {
		t.Fatal("Repository is not of ACL extended type *ACLSecurityMongoRepo.")
	}

	if _, ok := extended.(ACLRepository); !ok {
		t.Fatal("Repository cannot be used as ACLRepository.")
	}
}
