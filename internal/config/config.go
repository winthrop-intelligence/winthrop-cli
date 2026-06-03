package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/joho/godotenv"
)

const (
	EnvAuthBaseURL = "WINTHROP_AUTH_BASE_URL"
	EnvAPIBaseURL  = "WINTHROP_API_BASE_URL"
	EnvClientID    = "WINTHROP_CLIENT_ID"
	EnvScopes      = "WINTHROP_SCOPES"

	DefaultAuthBaseURL = "https://winad-hq.com"
	DefaultAPIBaseURL  = "https://api.winad-hq.com"
	DefaultClientID    = "R4QyAr5wFZ8NTihNnB_O_tgBMYS17wrUZvoxuj4MDs0"
	DefaultScopes      = "winad_read offline_access"
)

type Config struct {
	AuthBaseURL string
	APIBaseURL  string
	ClientID    string
	Scopes      []string
}

func Load() (Config, error) {
	if err := godotenv.Load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return Config{}, fmt.Errorf("load .env: %w", err)
	}
	return LoadFromLookup(os.LookupEnv)
}

func LoadFromLookup(lookup func(string) (string, bool)) (Config, error) {
	cfg := Config{
		AuthBaseURL: envString(lookup, EnvAuthBaseURL, DefaultAuthBaseURL),
		APIBaseURL:  envString(lookup, EnvAPIBaseURL, DefaultAPIBaseURL),
		ClientID:    envString(lookup, EnvClientID, DefaultClientID),
		Scopes:      strings.Fields(envString(lookup, EnvScopes, DefaultScopes)),
	}

	var missing []string
	for _, item := range []struct {
		name  string
		value string
	}{
		{EnvAuthBaseURL, cfg.AuthBaseURL},
		{EnvAPIBaseURL, cfg.APIBaseURL},
		{EnvClientID, cfg.ClientID},
	} {
		if item.value == "" {
			missing = append(missing, item.name)
		}
	}
	if len(missing) > 0 {
		return Config{}, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	var err error
	cfg.AuthBaseURL, err = normalizeBaseURL(cfg.AuthBaseURL, EnvAuthBaseURL)
	if err != nil {
		return Config{}, err
	}
	cfg.APIBaseURL, err = normalizeBaseURL(cfg.APIBaseURL, EnvAPIBaseURL)
	if err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func (c Config) DeviceAuthorizationURL() string {
	return c.AuthBaseURL + "/oauth/authorize_device"
}

func (c Config) TokenURL() string {
	return c.AuthBaseURL + "/oauth/token"
}

func (c Config) MeURL() string {
	return c.APIBaseURL + "/api/v1/users/me"
}

func (c Config) ScopeString() string {
	return strings.Join(c.Scopes, " ")
}

func envString(lookup func(string) (string, bool), name string, defaultValue string) string {
	value, ok := lookup(name)
	if !ok {
		return defaultValue
	}
	return strings.TrimSpace(value)
}

func normalizeBaseURL(raw string, envName string) (string, error) {
	if raw == "" {
		return "", errors.New("empty base URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("%s must be an absolute URL", envName)
	}
	if parsed.Scheme != "https" && parsed.Scheme != "http" {
		return "", fmt.Errorf("%s must use http or https", envName)
	}
	if parsed.Scheme == "http" && !isLocalhost(parsed.Hostname()) {
		return "", fmt.Errorf("%s must use https unless the host is localhost, 127.0.0.1, or ::1", envName)
	}
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return strings.TrimRight(parsed.String(), "/"), nil
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}
