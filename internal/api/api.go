package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	Config config.Config
	HTTP   HTTPDoer
}

type Identity map[string]any

func (c Client) Me(ctx context.Context, accessToken string) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Config.MeURL(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}
	var identity Identity
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&identity); err != nil {
		return nil, fmt.Errorf("decode API response: %w", err)
	}
	return identity, nil
}

func (c Client) Reachable(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.Config.APIBaseURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func Subject(identity Identity) string {
	for _, key := range []string{"sub", "id", "user_id", "email", "username"} {
		if value, ok := identity[key]; ok {
			text := strings.TrimSpace(formatValue(value))
			if text != "" && text != "<nil>" {
				return text
			}
		}
	}
	return ""
}

func Summary(identity Identity) string {
	var parts []string
	for _, key := range []string{"id", "sub", "email", "username", "name", "scopes", "scope"} {
		if value, ok := identity[key]; ok {
			text := strings.TrimSpace(formatValue(value))
			if text != "" && text != "<nil>" {
				parts = append(parts, key+"="+text)
			}
		}
	}
	if len(parts) == 0 {
		return "authenticated"
	}
	return strings.Join(parts, "\n")
}

func formatValue(value any) string {
	switch v := value.(type) {
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case float32:
		return strconv.FormatFloat(float64(v), 'f', -1, 32)
	default:
		return fmt.Sprint(value)
	}
}

func (c Client) httpClient() HTTPDoer {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}
