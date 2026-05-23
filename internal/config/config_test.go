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

func TestLoadFromLookupRequiresEnv(t *testing.T) {
	_, err := LoadFromLookup(func(string) (string, bool) {
		return "", false
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
