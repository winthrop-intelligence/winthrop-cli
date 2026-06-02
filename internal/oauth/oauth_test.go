package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
)

func TestRequestDeviceAuthorization(t *testing.T) {
	var body string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/oauth/authorize_device" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		body = r.Form.Encode()
		_ = json.NewEncoder(w).Encode(DeviceAuthorization{
			DeviceCode:      "device",
			UserCode:        "user",
			VerificationURI: "https://verify.example.com",
			ExpiresIn:       600,
			Interval:        1,
		})
	}))
	defer server.Close()

	client := Client{Config: config.Config{AuthBaseURL: server.URL, ClientID: "client", Scopes: []string{"read", "write"}}, HTTP: server.Client()}
	device, err := client.RequestDeviceAuthorization(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if device.DeviceCode != "device" || !strings.Contains(body, "scope=read+write") {
		t.Fatalf("unexpected device=%+v body=%q", device, body)
	}
}

func TestPollTokenHandlesPendingThenSuccess(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access", RefreshToken: "refresh"})
	}))
	defer server.Close()

	client := Client{Config: config.Config{AuthBaseURL: server.URL, ClientID: "client"}, HTTP: server.Client()}
	start := time.Now()
	token, err := client.PollToken(context.Background(), DeviceAuthorization{DeviceCode: "device", Interval: 1})
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "access" || attempts != 2 {
		t.Fatalf("token=%+v attempts=%d", token, attempts)
	}
	if time.Since(start) < time.Second {
		t.Fatal("expected polling interval delay")
	}
}

func TestPollTokenAcceptsResponseWithoutRefreshToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access"})
	}))
	defer server.Close()

	client := Client{Config: config.Config{AuthBaseURL: server.URL, ClientID: "client"}, HTTP: server.Client()}
	token, err := client.PollToken(context.Background(), DeviceAuthorization{DeviceCode: "device", Interval: 1})
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "access" || token.RefreshToken != "" {
		t.Fatalf("token=%+v", token)
	}
}

func TestRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "old" {
			t.Fatalf("form = %v", r.Form)
		}
		_ = json.NewEncoder(w).Encode(TokenResponse{AccessToken: "access", RefreshToken: "new"})
	}))
	defer server.Close()

	client := Client{Config: config.Config{AuthBaseURL: server.URL, ClientID: "client"}, HTTP: server.Client()}
	token, err := client.Refresh(context.Background(), "old")
	if err != nil {
		t.Fatal(err)
	}
	if token.AccessToken != "access" || token.RefreshToken != "new" {
		t.Fatalf("token = %+v", token)
	}
}
