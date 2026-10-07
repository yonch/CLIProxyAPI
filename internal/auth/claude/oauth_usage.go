package claude

import (
	"context"
	"fmt"
	"net/http"
)

// claudeOAuthUsageURL is the subscription usage endpoint Claude Code reads.
const claudeOAuthUsageURL = "https://api.anthropic.com/api/oauth/usage"

// NewClaudeAuthWithRoundTripper creates a ClaudeAuth whose requests go through rt
// instead of the control-plane uTLS transport.
func NewClaudeAuthWithRoundTripper(rt http.RoundTripper) *ClaudeAuth {
	return &ClaudeAuth{httpClient: &http.Client{Transport: rt}}
}

// FetchOAuthUsage reads the account's subscription usage with the request shape
// Claude Code's API client sends: the Axios control-plane headers with the CLI
// User-Agent and the OAuth beta, and no Cache-Control. Redirects are not followed,
// so the token reaches only the usage endpoint. It returns the decoded body.
func (o *ClaudeAuth) FetchOAuthUsage(ctx context.Context, accessToken, userAgent string) ([]byte, error) {
	if o == nil || o.httpClient == nil {
		return nil, fmt.Errorf("fetch Claude OAuth usage: HTTP client is nil")
	}
	client := *o.httpClient
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	usage := &ClaudeAuth{httpClient: &client}
	return usage.fetchOAuthControlPlaneJSON(ctx, claudeOAuthUsageURL, accessToken, "usage", func(header http.Header) {
		header.Del("Cache-Control")
		header.Set("User-Agent", userAgent)
		header.Set("anthropic-beta", "oauth-2025-04-20")
	})
}
