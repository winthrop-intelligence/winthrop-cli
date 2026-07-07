package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
)

const maxResponseBodyBytes = 1 << 20

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	Config config.Config
	HTTP   HTTPDoer
}

type Request struct {
	Method      string
	Path        string
	AccessToken string
}

type Response struct {
	Method     string
	URL        string
	StatusCode int
	Header     http.Header
	Body       []byte
	Elapsed    time.Duration
}

type StreamResponse struct {
	Method     string
	URL        string
	StatusCode int
	Header     http.Header
	Body       io.ReadCloser
	Elapsed    time.Duration
}

type Identity map[string]any

func (c Client) Me(ctx context.Context, accessToken string) (Identity, error) {
	resp, err := c.Do(ctx, Request{
		Method:      http.MethodGet,
		Path:        "/api/v1/users/me",
		AccessToken: accessToken,
	})
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, fmt.Errorf("API returned HTTP %d", resp.StatusCode)
	}
	var identity Identity
	decoder := json.NewDecoder(bytes.NewReader(resp.Body))
	decoder.UseNumber()
	if err := decoder.Decode(&identity); err != nil {
		return nil, fmt.Errorf("decode API response: %w", err)
	}
	return identity, nil
}

func (c Client) Do(ctx context.Context, request Request) (Response, error) {
	resp, err := c.Stream(ctx, request)
	if err != nil {
		return Response{}, err
	}
	defer resp.Body.Close()

	body, err := readLimited(resp.Body, maxResponseBodyBytes)
	if err != nil {
		return Response{}, err
	}
	return Response{
		Method:     resp.Method,
		URL:        resp.URL,
		StatusCode: resp.StatusCode,
		Header:     resp.Header,
		Body:       body,
		Elapsed:    resp.Elapsed,
	}, nil
}

func (c Client) Stream(ctx context.Context, request Request) (StreamResponse, error) {
	method := request.Method
	if method == "" {
		method = http.MethodGet
	}
	endpoint, err := c.ResolvePath(request.Path)
	if err != nil {
		return StreamResponse{}, err
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint, nil)
	if err != nil {
		return StreamResponse{}, err
	}
	if request.AccessToken == "" {
		return StreamResponse{}, errors.New("missing access token")
	}
	req.Header.Set("Authorization", "Bearer "+request.AccessToken)
	req.Header.Set("Accept", "application/json")

	start := time.Now()
	resp, err := c.httpClient().Do(req)
	elapsed := time.Since(start)
	if err != nil {
		return StreamResponse{}, err
	}
	return StreamResponse{
		Method:     method,
		URL:        endpoint,
		StatusCode: resp.StatusCode,
		Header:     resp.Header.Clone(),
		Body:       resp.Body,
		Elapsed:    elapsed,
	}, nil
}

func (c Client) ResolvePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("API path is required")
	}
	parsed, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("parse API path: %w", err)
	}
	if parsed.IsAbs() || parsed.Host != "" || strings.HasPrefix(path, "//") {
		return "", errors.New("API path must be relative to the configured API base URL")
	}
	if !strings.HasPrefix(path, "/") {
		return "", errors.New("API path must start with /")
	}
	base, err := url.Parse(c.Config.APIBaseURL)
	if err != nil {
		return "", err
	}
	base.Path = strings.TrimRight(base.Path, "/") + "/" + strings.TrimLeft(parsed.Path, "/")
	base.RawQuery = parsed.RawQuery
	base.Fragment = parsed.Fragment
	return base.String(), nil
}

func readLimited(r io.Reader, limit int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("API response body exceeds %d bytes", limit)
	}
	return body, nil
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
