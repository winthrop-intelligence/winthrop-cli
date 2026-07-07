package api

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
)

func TestResolvePathPreservesQuery(t *testing.T) {
	client := Client{Config: config.Config{APIBaseURL: "https://api.example.com/base"}}

	got, err := client.ResolvePath("/api/v1/coaches.json?q[first_name_eq]=Jason")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://api.example.com/base/api/v1/coaches.json?q[first_name_eq]=Jason"
	if got != want {
		t.Fatalf("ResolvePath = %q, want %q", got, want)
	}
}

func TestResolvePathRejectsInvalidPaths(t *testing.T) {
	client := Client{Config: config.Config{APIBaseURL: "https://api.example.com"}}
	for _, path := range []string{
		"",
		"api/v1/users/me",
		"https://api.example.com/api/v1/users/me",
		"//api.example.com/api/v1/users/me",
	} {
		t.Run(path, func(t *testing.T) {
			if _, err := client.ResolvePath(path); err == nil {
				t.Fatal("ResolvePath error = nil")
			}
		})
	}
}

func TestDoSendsAuthHeadersAndReturnsRawResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method = %s", r.Method)
		}
		if r.URL.RequestURI() != "/api/v1/coaches.json?q[first_name_eq]=Jason" {
			t.Fatalf("request URI = %q", r.URL.RequestURI())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer access-token" {
			t.Fatalf("Authorization = %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Fatalf("Accept = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	client := Client{
		Config: config.Config{APIBaseURL: server.URL},
		HTTP:   server.Client(),
	}
	resp, err := client.Do(context.Background(), Request{
		Method:      http.MethodGet,
		Path:        "/api/v1/coaches.json?q[first_name_eq]=Jason",
		AccessToken: "access-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Method != http.MethodGet {
		t.Fatalf("Method = %q", resp.Method)
	}
	if !strings.HasPrefix(resp.URL, server.URL+"/api/v1/coaches.json") {
		t.Fatalf("URL = %q", resp.URL)
	}
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("StatusCode = %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("Content-Type = %q", resp.Header.Get("Content-Type"))
	}
	if string(resp.Body) != `{"ok":true}` {
		t.Fatalf("Body = %q", resp.Body)
	}
	if resp.Elapsed <= 0 {
		t.Fatalf("Elapsed = %s", resp.Elapsed)
	}
}

func TestStreamLeavesBodyReadable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(server.Close)

	client := Client{
		Config: config.Config{APIBaseURL: server.URL},
		HTTP:   server.Client(),
	}
	resp, err := client.Stream(context.Background(), Request{
		Path:        "/stream",
		AccessToken: "access-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"ok":true}` {
		t.Fatalf("stream body = %q", body)
	}
}

func TestDoRejectsOversizedResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, maxResponseBodyBytes+1))
	}))
	t.Cleanup(server.Close)

	client := Client{
		Config: config.Config{APIBaseURL: server.URL},
		HTTP:   server.Client(),
	}
	_, err := client.Do(context.Background(), Request{
		Path:        "/too-large",
		AccessToken: "access-token",
	})
	if err == nil {
		t.Fatal("Do error = nil")
	}
	if !strings.Contains(err.Error(), "API response body exceeds") {
		t.Fatalf("error = %v", err)
	}
}

func TestDoReturnsNon2xxResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"error":"missing"}`))
	}))
	t.Cleanup(server.Close)

	client := Client{
		Config: config.Config{APIBaseURL: server.URL},
		HTTP:   server.Client(),
	}
	resp, err := client.Do(context.Background(), Request{
		Path:        "/missing",
		AccessToken: "access-token",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("StatusCode = %d", resp.StatusCode)
	}
	if string(resp.Body) != `{"error":"missing"}` {
		t.Fatalf("Body = %q", resp.Body)
	}
}

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
