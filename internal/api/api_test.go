package api

import (
	"strings"
	"testing"
)

func TestSummaryAndSubject(t *testing.T) {
	identity := Identity{
		"id":     "123",
		"email":  "user@example.com",
		"scopes": []any{"read", "write"},
	}

	if got := Subject(identity); got != "123" {
		t.Fatalf("Subject = %q", got)
	}
	got := Summary(identity)
	for _, want := range []string{"id=123", "email=user@example.com", "scopes=[read write]"} {
		if !strings.Contains(got, want) {
			t.Fatalf("Summary = %q, want %q", got, want)
		}
	}
}
