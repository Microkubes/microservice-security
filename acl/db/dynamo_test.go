package db

import (
	"fmt"
	"testing"

	"github.com/Microkubes/backends"

	"github.com/ory/ladon/compiler"
)

func TestLadonRegexCompiler(t *testing.T) {
	compiled, err := compiler.CompileRegex("", byte('^'), byte('$'))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(compiled)
}

func TestACLSecurityDynamoRepoExtender(t *testing.T) {
	inRepo := &backends.DynamoCollection{}

	outRepo := ACLSecurityDynamoRepoExtender(inRepo)

	if _, ok := outRepo.(*ACLSecurityDynamoRepo); !ok {
		t.Fatalf("Expected the extender to extend the in repository as *ACLSecurityDunamoRepo")
	}
}

func TestMatchAny(t *testing.T) {
	match, err := matchAny([]string{"/not-this", "/path", "/path/.+"}, "/path/subpath")
	if err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Fatal("Expected to match at least one of the patterns.")
	}

	match, err = matchAny([]string{}, "/path/subpath")
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Fatal("Should not match empty patterns.")
	}

	match, err = matchAny([]string{}, "")
	if err != nil {
		t.Fatal(err)
	}
	if match {
		t.Fatal("Should not match empty patterns to empty string.")
	}

}

func TestMatchAnySafe(t *testing.T) {
	if matchAnySafe([]string{"/a", "/path/invalid"}, "/path/subpath") {
		t.Fatal("Should not match.")
	}

	if !matchAnySafe([]string{"^/", "^/path"}, "/path/subpath") {
		t.Fatal("Should match.")
	}

	if !matchAnySafe([]string{"/", "/path", "/path/.+"}, "/path/subpath") {
		t.Fatal("Expected the last pattern to match the input.")
	}

	if matchAnySafe([]string{}, "/path/subpath") {
		t.Fatal("Should not match against empty patterns.")
	}

	if matchAnySafe([]string{}, "") {
		t.Fatal("Should not match empty string against empty patterns.")
	}
}
