package oauth

import (
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

const (
	DefaultPollInterval = 5 * time.Second
	SlowDownIncrement   = 5 * time.Second
)

var (
	ErrAuthorizationPending = errors.New("authorization pending")
	ErrSlowDown             = errors.New("slow down")
	ErrAccessDenied         = errors.New("access denied")
	ErrExpiredToken         = errors.New("device code expired")
)

type HTTPDoer interface {
	Do(*http.Request) (*http.Response, error)
}

type Client struct {
	Config config.Config
	HTTP   HTTPDoer
}

type DeviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
	Message                 string `json:"message"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type oauthError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

func (c Client) RequestDeviceAuthorization(ctx context.Context) (DeviceAuthorization, error) {
	form := url.Values{}
	form.Set("client_id", c.Config.ClientID)
	if scope := c.Config.ScopeString(); scope != "" {
		form.Set("scope", scope)
	}

	var device DeviceAuthorization
	if err := c.postForm(ctx, c.Config.DeviceAuthorizationURL(), form, &device); err != nil {
		return DeviceAuthorization{}, err
	}
	if device.DeviceCode == "" || device.UserCode == "" || device.VerificationURI == "" {
		return DeviceAuthorization{}, errors.New("device authorization response missing required fields")
	}
	return device, nil
}

func (c Client) PollToken(ctx context.Context, device DeviceAuthorization) (TokenResponse, error) {
	interval := DefaultPollInterval
	if device.Interval > 0 {
		interval = time.Duration(device.Interval) * time.Second
	}

	for {
		token, err := c.exchangeDeviceCode(ctx, device.DeviceCode)
		if err == nil {
			return token, nil
		}
		switch {
		case errors.Is(err, ErrAuthorizationPending):
		case errors.Is(err, ErrSlowDown):
			interval += SlowDownIncrement
		default:
			return TokenResponse{}, err
		}

		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return TokenResponse{}, ctx.Err()
		case <-timer.C:
		}
	}
}

func (c Client) Refresh(ctx context.Context, refreshToken string) (TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("client_id", c.Config.ClientID)
	form.Set("refresh_token", refreshToken)

	var token TokenResponse
	if err := c.postForm(ctx, c.Config.TokenURL(), form, &token); err != nil {
		return TokenResponse{}, err
	}
	if token.AccessToken == "" {
		return TokenResponse{}, errors.New("token response missing access_token")
	}
	return token, nil
}

func (c Client) exchangeDeviceCode(ctx context.Context, deviceCode string) (TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:device_code")
	form.Set("client_id", c.Config.ClientID)
	form.Set("device_code", deviceCode)

	var token TokenResponse
	if err := c.postForm(ctx, c.Config.TokenURL(), form, &token); err != nil {
		return TokenResponse{}, err
	}
	if token.AccessToken == "" {
		return TokenResponse{}, errors.New("token response missing access_token")
	}
	return token, nil
}

func (c Client) postForm(ctx context.Context, endpoint string, form url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseOAuthError(resp.StatusCode, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("decode OAuth response: %w", err)
	}
	return nil
}

func (c Client) httpClient() HTTPDoer {
	if c.HTTP != nil {
		return c.HTTP
	}
	return http.DefaultClient
}

func parseOAuthError(status int, body []byte) error {
	var oe oauthError
	if err := json.Unmarshal(body, &oe); err == nil {
		switch oe.Error {
		case "authorization_pending":
			return ErrAuthorizationPending
		case "slow_down":
			return ErrSlowDown
		case "access_denied":
			return ErrAccessDenied
		case "expired_token":
			return ErrExpiredToken
		}
		if oe.Error != "" {
			if oe.ErrorDescription != "" {
				return fmt.Errorf("%s: %s", oe.Error, oe.ErrorDescription)
			}
			return errors.New(oe.Error)
		}
	}
	return errors.New("OAuth server returned HTTP " + strconv.Itoa(status))
}
