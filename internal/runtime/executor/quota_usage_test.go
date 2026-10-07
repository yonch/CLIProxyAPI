package executor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type quotaUsageRoundTripper func(*http.Request) (*http.Response, error)

func (f quotaUsageRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func quotaUsageRecorder(status int, body string, location string) (context.Context, func() []*http.Request) {
	var mu sync.Mutex
	var seen []*http.Request
	rt := quotaUsageRoundTripper(func(req *http.Request) (*http.Response, error) {
		mu.Lock()
		seen = append(seen, req.Clone(context.Background()))
		mu.Unlock()
		header := http.Header{"Content-Type": {"application/json"}}
		if location != "" {
			header.Set("Location", location)
		}
		return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", http.RoundTripper(rt))
	return ctx, func() []*http.Request {
		mu.Lock()
		defer mu.Unlock()
		return append([]*http.Request(nil), seen...)
	}
}

func quotaUsageClaudeAuth(metadata map[string]any) *cliproxyauth.Auth {
	meta := map[string]any{"type": "claude", "access_token": "sk-ant-oat01-test-token"}
	for key, value := range metadata {
		meta[key] = value
	}
	return &cliproxyauth.Auth{ID: "claude-a", Provider: "claude", Metadata: meta}
}

func TestClaudeReadQuotaUsageRequest(t *testing.T) {
	const body = `{"seven_day":{"utilization":31,"resets_at":"2030-01-01T00:00:00Z"},"five_hour":{"utilization":14,"resets_at":"2030-01-01T01:00:00Z"}}`
	ctx, seen := quotaUsageRecorder(http.StatusOK, body, "")
	cfg := &config.Config{}
	got, err := NewClaudeExecutor(cfg).ReadQuotaUsage(ctx, quotaUsageClaudeAuth(nil))
	if err != nil || string(got) != body {
		t.Fatalf("ReadQuotaUsage = %q, %v", got, err)
	}
	reqs := seen()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	req := reqs[0]
	if req.Method != http.MethodGet || req.URL.String() != "https://api.anthropic.com/api/oauth/usage" {
		t.Fatalf("request = %s %s", req.Method, req.URL)
	}
	for name, want := range map[string]string{
		"Authorization":  "Bearer sk-ant-oat01-test-token",
		"Anthropic-Beta": "oauth-2025-04-20",
		"User-Agent":     helps.ClaudeUsageUserAgent(cfg),
		"Cache-Control":  "",
	} {
		if got := req.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
}

func TestClaudeReadQuotaUsageRefusesIneligibleCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		exec interface {
			ReadQuotaUsage(context.Context, *cliproxyauth.Auth) ([]byte, error)
		}
		auth *cliproxyauth.Auth
	}{
		{"setup token scope", NewClaudeExecutor(nil), quotaUsageClaudeAuth(map[string]any{"scope": "user:inference"})},
		{"setup token flag", NewClaudeExecutor(nil), quotaUsageClaudeAuth(map[string]any{"setup_token": true})},
		{"api key token", NewClaudeExecutor(nil), quotaUsageClaudeAuth(map[string]any{"access_token": "sk-ant-api03-test-key"})},
		{"api key attribute", NewClaudeExecutor(nil), func() *cliproxyauth.Auth {
			a := quotaUsageClaudeAuth(nil)
			a.Attributes = map[string]string{"api_key": "sk-ant-api03-test-key"}
			return a
		}()},
		{"kimi embeds claude", NewKimiExecutor(nil), func() *cliproxyauth.Auth {
			a := quotaUsageClaudeAuth(nil)
			a.Provider = "kimi"
			return a
		}()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, seen := quotaUsageRecorder(http.StatusOK, `{}`, "")
			_, err := tc.exec.ReadQuotaUsage(ctx, tc.auth)
			if !errors.Is(err, cliproxyauth.ErrQuotaUsageNotEligible) {
				t.Fatalf("err = %v, want ineligible", err)
			}
			if n := len(seen()); n != 0 {
				t.Fatalf("ineligible credential sent %d requests", n)
			}
		})
	}
}

func TestCodexReadQuotaUsageRequest(t *testing.T) {
	const body = `{"rate_limit":{"primary_window":{"limit_window_seconds":604800,"reset_at":1893456000},"secondary_window":null}}`
	auth := &cliproxyauth.Auth{ID: "codex-a", Provider: "codex", Metadata: map[string]any{"type": "codex", "access_token": "test-codex-token", "account_id": "account-a"}}
	for _, exec := range []interface {
		ReadQuotaUsage(context.Context, *cliproxyauth.Auth) ([]byte, error)
	}{NewCodexExecutor(&config.Config{}), NewCodexAutoExecutor(&config.Config{})} {
		ctx, seen := quotaUsageRecorder(http.StatusOK, body, "")
		got, err := exec.ReadQuotaUsage(ctx, auth)
		if err != nil || string(got) != body {
			t.Fatalf("ReadQuotaUsage = %q, %v", got, err)
		}
		reqs := seen()
		if len(reqs) != 1 {
			t.Fatalf("requests = %d, want 1", len(reqs))
		}
		req := reqs[0]
		if req.Method != http.MethodGet || req.URL.String() != "https://chatgpt.com/backend-api/wham/usage" {
			t.Fatalf("request = %s %s", req.Method, req.URL)
		}
		for name, want := range map[string]string{
			"Authorization":      "Bearer test-codex-token",
			"Chatgpt-Account-Id": "account-a",
			"Originator":         codexOriginator,
			"User-Agent":         codexUserAgent,
		} {
			if got := req.Header.Get(name); got != want {
				t.Errorf("%s = %q, want %q", name, got, want)
			}
		}
	}

	apiKey := &cliproxyauth.Auth{ID: "codex-key", Provider: "codex", Attributes: map[string]string{"api_key": "test-api-key"}}
	ctx, seen := quotaUsageRecorder(http.StatusOK, body, "")
	if _, err := NewCodexExecutor(nil).ReadQuotaUsage(ctx, apiKey); !errors.Is(err, cliproxyauth.ErrQuotaUsageNotEligible) || len(seen()) != 0 {
		t.Fatalf("API-key credential: err=%v requests=%d, want ineligible without requests", err, len(seen()))
	}
}

// TestReadQuotaUsageFailuresAndRedirects checks that non-2xx responses are errors and that
// a redirect is never followed, so the bearer token reaches only the usage endpoint.
func TestReadQuotaUsageFailuresAndRedirects(t *testing.T) {
	codexAuth := &cliproxyauth.Auth{ID: "codex-a", Provider: "codex", Metadata: map[string]any{"access_token": "test-codex-token"}}
	for _, tc := range []struct {
		name, location string
		status         int
	}{
		{name: "unauthorized", status: http.StatusUnauthorized},
		{name: "rate limited", status: http.StatusTooManyRequests},
		{name: "redirect", status: http.StatusFound, location: "https://untrusted.example/collect"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, seen := quotaUsageRecorder(tc.status, `{"error":"x"}`, tc.location)
			if _, err := NewClaudeExecutor(nil).ReadQuotaUsage(ctx, quotaUsageClaudeAuth(nil)); err == nil {
				t.Error("claude read succeeded")
			}
			if _, err := NewCodexExecutor(nil).ReadQuotaUsage(ctx, codexAuth); err == nil {
				t.Error("codex read succeeded")
			}
			for _, req := range seen() {
				if req.URL.Host == "untrusted.example" {
					t.Fatal("redirect was followed")
				}
			}
		})
	}
}

// TestReadQuotaUsageUsesCredentialProxy checks that a credential proxy takes precedence over
// the context transport, as it does for inference, instead of being bypassed.
func TestReadQuotaUsageUsesCredentialProxy(t *testing.T) {
	var mu sync.Mutex
	var targets []string
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		targets = append(targets, r.Method+" "+r.Host)
		mu.Unlock()
		http.Error(w, "denied", http.StatusForbidden)
	}))
	defer proxy.Close()

	claudeAuth := quotaUsageClaudeAuth(nil)
	claudeAuth.ProxyURL = proxy.URL
	codexAuth := &cliproxyauth.Auth{ID: "codex-a", Provider: "codex", ProxyURL: proxy.URL, Metadata: map[string]any{"access_token": "test-codex-token"}}
	ctx, seen := quotaUsageRecorder(http.StatusOK, `{}`, "")
	if _, err := NewClaudeExecutor(&config.Config{}).ReadQuotaUsage(ctx, claudeAuth); err == nil {
		t.Error("claude read through a refusing proxy succeeded")
	}
	if _, err := NewCodexExecutor(&config.Config{}).ReadQuotaUsage(ctx, codexAuth); err == nil {
		t.Error("codex read through a refusing proxy succeeded")
	}
	if n := len(seen()); n != 0 {
		t.Fatalf("context transport used %d times despite a credential proxy", n)
	}
	mu.Lock()
	defer mu.Unlock()
	want := map[string]bool{"CONNECT api.anthropic.com:443": true, "CONNECT chatgpt.com:443": true}
	for _, target := range targets {
		delete(want, target)
	}
	if len(want) != 0 {
		t.Fatalf("proxy saw %v, missing %v", targets, want)
	}
}
