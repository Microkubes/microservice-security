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

///////////////////////

type TokenType int

const (
	TokenString TokenType = iota
	Pattern     TokenType = iota
)

type Token interface {
	Type() TokenType
	Value() string
	Repr() string
}

type policyToken struct {
	tokenType TokenType
	value     string
}

func (t *policyToken) Type() TokenType {
	return t.tokenType
}

func (t *policyToken) Value() string {
	return t.value
}

func (t *policyToken) Repr() string {
	tokenType := "PATTERN"
	if t.tokenType == TokenString {
		tokenType = "STRING"
	}
	return fmt.Sprintf("Token<%s>:%s", tokenType, t.value)
}

func Tokenize(pattern string, startDelim, endDelim rune, strict bool) ([]Token, error) {
	const (
		None       int = iota
		PatternExp int = iota
		String     int = iota
	)

	var prev rune
	state := None
	patterns := 0

	tokens := []Token{}
	currToken := ""

	for _, chr := range pattern {
		if chr == startDelim {
			if state == String && prev == '\\' {
				currToken += string(chr)
				prev = chr
				continue
			}
			if state == PatternExp {
				// we're already in a pattern so append this
				currToken += string(chr)
				prev = chr
				continue
			}
			if state == String {
				// create new string token
				tokens = append(tokens, &policyToken{
					tokenType: TokenString,
					value:     currToken,
				})
			}
			currToken = ""
			state = PatternExp
			patterns++
		} else if chr == endDelim {
			if state == String && prev == '\\' {
				currToken += string(chr)
				prev = chr
				continue
			}
			if state == None || state == String {
				// error
				if strict {
					return nil, fmt.Errorf("invalid end delimiter at beginning of pattern string")
				}
				// ignore it if not strict
				prev = chr
				continue
			}
			patterns--
			if state == PatternExp {
				if patterns == 0 {
					// close the pattern, add the token to the list of tokens
					state = String
					tokens = append(tokens, &policyToken{
						tokenType: Pattern,
						value:     currToken,
					})
					currToken = ""
					prev = chr
					continue
				}
				// append the endDelim to the string
				currToken += string(chr)
				prev = chr
			}
		} else {
			if state == None {
				state = String
			}
			// append them as they come
			currToken += string(chr)
			prev = chr
		}
	}
	if state == PatternExp {
		if strict {
			return nil, fmt.Errorf("pattern expression not closed at end of string - was looking at: %s", currToken)
		}
	}
	if state == String && currToken != "" {
		tokens = append(tokens, &policyToken{
			tokenType: TokenString,
			value:     currToken,
		})
	}
	return tokens, nil
}

////////////////////////////////

func TestTokenize(t *testing.T) {
	tokens, err := Tokenize("/some<a|b>string/pls<hahaha>", '<', '>', true)
	if err != nil {
		t.Fatal(err)
	}
	for _, t := range tokens {
		fmt.Println("  * Token: ", t.Repr())
	}
}
