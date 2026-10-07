package helps

import (
	"context"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// ClaudeUsageUserAgent returns the Claude Code User-Agent a usage read carries: the
// configured CLI baseline.
func ClaudeUsageUserAgent(cfg *config.Config) string {
	return defaultClaudeDeviceProfile(cfg).UserAgent
}

// EffectiveProxyURL returns the proxy NewUtlsHTTPClient and NewProxyAwareHTTPClient use:
// the request-scoped override, then the credential proxy, then the global proxy.
func EffectiveProxyURL(ctx context.Context, cfg *config.Config, auth *cliproxyauth.Auth) string {
	return effectiveProxyURL(ctx, cfg, auth)
}
