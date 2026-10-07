package executor

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	claudeauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/claude"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

var _ cliproxyauth.QuotaUsageReader = (*ClaudeExecutor)(nil)

var errClaudeQuotaUsageUnsupported = fmt.Errorf("claude quota usage requires a full OAuth credential: %w", cliproxyauth.ErrQuotaUsageNotEligible)

// ReadQuotaUsage reads the credential's subscription usage the way Claude Code does:
// through the OAuth control-plane transport with the configured Claude Code User-Agent.
// Only full OAuth access tokens are sent. API keys and setup tokens, which cannot read
// the usage endpoint, are refused without network access.
func (e *ClaudeExecutor) ReadQuotaUsage(ctx context.Context, auth *cliproxyauth.Auth) ([]byte, error) {
	if auth == nil || !strings.EqualFold(auth.Provider, "claude") || strings.TrimSpace(auth.Attributes["api_key"]) != "" {
		return nil, errClaudeQuotaUsageUnsupported
	}
	accessToken := strings.TrimSpace(claudeauth.ReadMetadataString(&auth.Metadata, "access_token"))
	if !isClaudeOAuthToken(accessToken) || isClaudeSetupToken(auth, accessToken) {
		return nil, errClaudeQuotaUsageUnsupported
	}
	return e.claudeOAuthUsageService(ctx, auth).FetchOAuthUsage(ctx, accessToken, helps.ClaudeUsageUserAgent(e.cfg))
}

// claudeOAuthUsageService resolves the proxy the way helps.NewUtlsHTTPClient does: the
// request-scoped override, then the credential proxy, then the global proxy. A round
// tripper injected through the context replaces the transport only when no proxy applies.
func (e *ClaudeExecutor) claudeOAuthUsageService(ctx context.Context, auth *cliproxyauth.Auth) *claudeauth.ClaudeAuth {
	proxyURL := helps.EffectiveProxyURL(ctx, e.cfg, auth)
	if proxyURL == "" {
		if rt, ok := ctx.Value("cliproxy.roundtripper").(http.RoundTripper); ok && rt != nil {
			return claudeauth.NewClaudeAuthWithRoundTripper(rt)
		}
	}
	return claudeauth.NewClaudeAuthWithProxyURL(e.cfg, proxyURL)
}
