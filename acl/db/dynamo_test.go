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

func TestTokenize(t *testing.T) {
	tokens, err := Tokenize("/some<a|b>string/pls<hahaha>", '<', '>', true)
	if err != nil {
		t.Fatal(err)
	}
	for _, t := range tokens {
		fmt.Println("  * Token: ", t.Repr())
	}
}
