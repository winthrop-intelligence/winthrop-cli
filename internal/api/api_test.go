package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
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

func TestMePreservesNumericIDFormatting(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"id":1751883542,"email":"user@example.com"}`))
	}))
	t.Cleanup(server.Close)

	client := Client{
		Config: config.Config{APIBaseURL: server.URL},
		HTTP:   server.Client(),
	}

	identity, err := client.Me(context.Background(), "token")
	if err != nil {
		t.Fatalf("Me() error = %v", err)
	}
	if got := Subject(identity); got != "1751883542" {
		t.Fatalf("Subject = %q", got)
	}
	if got := Summary(identity); !strings.Contains(got, "id=1751883542") {
		t.Fatalf("Summary = %q, want integer id", got)
	}
}
