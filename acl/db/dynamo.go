package db

import (
	"fmt"
	"log"
	"sort"

	"github.com/JormungandrK/backends"
	//lru "github.com/hashicorp/golang-lru"
)

const DEBUG = true

const CacheSize = 128 // Keep the latest 128 policies in LRU cache.

type ACLSecurityDynamoRepo struct {
	*backends.DynamoCollection
	//cache *lru.Cache
}

func (a *ACLSecurityDynamoRepo) FindPolicies(filter map[string]string) ([]*PolicyRecord, error) {

	return nil, nil
}

func largestStringToken(pattern string, startDelim, endDelim rune) (string, error) {
	tokens, err := Tokenize(pattern, startDelim, endDelim, DEBUG)
	if err != nil {
		return "", err
	}
	if len(tokens) == 0 {
		return "", nil
	}
	tokens = filter(tokens, func(t Token) bool {
		return t.Type() == TokenString
	})
	sort.Slice(tokens, func(i, j int) bool {
		return len(tokens[i].Value()) > len(tokens[j].Value()) // descending
	})
	return tokens[0].Value(), nil
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

func filter(tokens []Token, f func(t Token) bool) []Token {
	filtered := []Token{}
	for _, token := range tokens {
		if f(token) {
			filtered = append(filtered, token)
		}
	}
	return filtered
}
