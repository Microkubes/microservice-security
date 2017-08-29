package oauth2

import "testing"

func TestGenerateRandomCode(t *testing.T) {
	for i := 1; i < 35; i++ {
		code, err := GenerateRandomCode(i)
		t.Logf("%d: %s", i, code)
		if err != nil {
			t.Fatal(err)
		}
		if len(code) != i {
			t.Fatal("Expected a string with length 10")
		}
	}

}
