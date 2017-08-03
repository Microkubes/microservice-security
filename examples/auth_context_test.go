package examples

import "testing"

func TestCallSetAuth(t *testing.T) {
	if err := SetAuthInContext(); err != nil {
		t.Fatal("Failed to call example for SetAuthInContext", err)
	}
}

func TestCallRetrieveAuth(t *testing.T) {
	if err := RetrieveAuthFromContext(); err != nil {
		t.Fatal("Failed to call example for RetrieveAuthFromContext", err)
	}
}
