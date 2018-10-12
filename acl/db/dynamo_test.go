package db

import (
	"fmt"
	"testing"

	"github.com/ory/ladon/compiler"
)

func TestLadonRegexCompiler(t *testing.T) {
	compiled, err := compiler.CompileRegex("", byte('^'), byte('$'))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(compiled)
}
