package store

import (
	"testing"

	"github.com/winthrop-intelligence/winthrop-cli/internal/config"
)

func TestKeyDerivation(t *testing.T) {
	cfg := config.Config{
		AuthBaseURL: "https://auth.example.com",
		ClientID:    "client",
	}

	if got, want := ActiveKey(cfg), "active:aae0b21a499b40236c6b5be6e38de3714cde58f7cb6da5e4a7bdd8cd29112f38"; got != want {
		t.Fatalf("ActiveKey() = %q, want %q", got, want)
	}
	if got, want := RefreshAccount(cfg, "subject"), "refresh:fb1d58b6973c2270a3d2146dc31aafa4352406f9d3a592d2603a81621c7c4d3c"; got != want {
		t.Fatalf("RefreshAccount() = %q, want %q", got, want)
	}
	if got, want := AccessAccount(RefreshAccount(cfg, "subject")), "access:66202bd0890d7234590566dcf5948848ab4293115026f77b42b2c4f21525a2f9"; got != want {
		t.Fatalf("AccessAccount() = %q, want %q", got, want)
	}
	if got, want := RefreshAccount(cfg, ""), "refresh:157e67be35265749423e0db63e61e933a94b99909f9df1035c74a05ff99e2b57"; got != want {
		t.Fatalf("RefreshAccount(empty) = %q, want %q", got, want)
	}
}
