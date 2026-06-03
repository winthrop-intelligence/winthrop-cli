package config

import (
	"strings"
	"testing"
)

func TestLoadFromLookupParsesEnv(t *testing.T) {
	values := map[string]string{
		EnvAuthBaseURL: "https://auth.example.com/",
		EnvAPIBaseURL:  "https://api.example.com/base/",
		EnvClientID:    "winthrop-cli",
		EnvScopes:      "read write",
	}

	cfg, err := LoadFromLookup(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.AuthBaseURL != "https://auth.example.com" {
		t.Fatalf("AuthBaseURL = %q", cfg.AuthBaseURL)
	}
	if cfg.APIBaseURL != "https://api.example.com/base" {
		t.Fatalf("APIBaseURL = %q", cfg.APIBaseURL)
	}
	if cfg.ScopeString() != "read write" {
		t.Fatalf("ScopeString = %q", cfg.ScopeString())
	}
	if cfg.MeURL() != "https://api.example.com/base/api/v1/users/me" {
		t.Fatalf("MeURL = %q", cfg.MeURL())
	}
}

func TestLoadFromLookupUsesDefaults(t *testing.T) {
	cfg, err := LoadFromLookup(func(string) (string, bool) {
		return "", false
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthBaseURL != DefaultAuthBaseURL {
		t.Fatalf("AuthBaseURL = %q", cfg.AuthBaseURL)
	}
	if cfg.APIBaseURL != DefaultAPIBaseURL {
		t.Fatalf("APIBaseURL = %q", cfg.APIBaseURL)
	}
	if cfg.ClientID != DefaultClientID {
		t.Fatalf("ClientID = %q", cfg.ClientID)
	}
	if cfg.ScopeString() != DefaultScopes {
		t.Fatalf("ScopeString = %q", cfg.ScopeString())
	}
}

func TestLoadFromLookupRejectsEmptyOverrides(t *testing.T) {
	values := map[string]string{
		EnvAuthBaseURL: "",
		EnvAPIBaseURL:  "",
		EnvClientID:    "",
	}

	_, err := LoadFromLookup(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err == nil {
		t.Fatal("expected error")
	}
	for _, name := range []string{EnvAuthBaseURL, EnvAPIBaseURL, EnvClientID} {
		if !strings.Contains(err.Error(), name) {
			t.Fatalf("error %q does not mention %s", err, name)
		}
	}
}

func TestLoadFromLookupRejectsHTTPForNonLocalhost(t *testing.T) {
	values := map[string]string{
		EnvAuthBaseURL: "http://auth.example.com",
		EnvAPIBaseURL:  "https://api.example.com",
		EnvClientID:    "winthrop-cli",
	}

	_, err := LoadFromLookup(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("error = %q", err)
	}
}

func TestLoadFromLookupAllowsHTTPForLocalhost(t *testing.T) {
	values := map[string]string{
		EnvAuthBaseURL: "http://localhost:8080",
		EnvAPIBaseURL:  "http://127.0.0.1:8081",
		EnvClientID:    "winthrop-cli",
	}

	cfg, err := LoadFromLookup(func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthBaseURL != "http://localhost:8080" {
		t.Fatalf("AuthBaseURL = %q", cfg.AuthBaseURL)
	}
}
