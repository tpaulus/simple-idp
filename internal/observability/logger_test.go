package observability

import "testing"

func TestNewLogger(t *testing.T) {
	if NewLogger("json") == nil || NewLogger("text") == nil {
		t.Fatal("expected logger")
	}
}
