package executor

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/util"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	log "github.com/sirupsen/logrus"
)

// codexUsageURL is the ChatGPT backend usage endpoint the Codex CLI reads.
const codexUsageURL = "https://chatgpt.com/backend-api/wham/usage"

// codexUsageMaxBodyBytes bounds a usage response, which is a small JSON document.
const codexUsageMaxBodyBytes = 1 << 20

var (
	_ cliproxyauth.QuotaUsageReader = (*CodexExecutor)(nil)
	_ cliproxyauth.QuotaUsageReader = (*CodexAutoExecutor)(nil)

	errCodexQuotaUsageUnsupported = fmt.Errorf("codex quota usage requires a ChatGPT OAuth credential: %w", cliproxyauth.ErrQuotaUsageNotEligible)
)

// ReadQuotaUsage reads the credential's ChatGPT usage with the transport and client
// identity HTTP inference uses for the same credential. API-key credentials are refused
// without network access, and redirects are not followed.
func (e *CodexExecutor) ReadQuotaUsage(ctx context.Context, auth *cliproxyauth.Auth) ([]byte, error) {
	if auth == nil || !strings.EqualFold(auth.Provider, "codex") || codexAuthUsesAPIKey(auth) {
		return nil, errCodexQuotaUsageUnsupported
	}
	accessToken, _ := auth.Metadata["access_token"].(string)
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return nil, errCodexQuotaUsageUnsupported
	}
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, codexUsageURL, nil)
	if errRequest != nil {
		return nil, fmt.Errorf("create codex usage request: %w", errRequest)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+accessToken)
	cfgUserAgent, _ := codexHeaderDefaults(e.cfg, auth)
	ensureHeaderWithConfigPrecedence(req.Header, nil, "User-Agent", cfgUserAgent, codexUserAgent)
	req.Header.Set("Originator", codexOriginator)
	if accountID, _ := auth.Metadata["account_id"].(string); strings.TrimSpace(accountID) != "" {
		req.Header.Set("Chatgpt-Account-Id", accountID)
	}
	util.ApplyCustomHeadersFromAttrs(req, auth.Attributes)
	applyCodexCloakingHeaders(req.Header, e.cfg, auth)

	client := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, errDo := client.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("fetch codex usage: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Errorf("failed to close codex usage response body: %v", errClose)
		}
	}()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch codex usage failed with status %d", resp.StatusCode)
	}
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, codexUsageMaxBodyBytes))
	if errRead != nil {
		return nil, fmt.Errorf("read codex usage response: %w", errRead)
	}
	return body, nil
}

// ReadQuotaUsage reads usage through the HTTP executor.
func (e *CodexAutoExecutor) ReadQuotaUsage(ctx context.Context, auth *cliproxyauth.Auth) ([]byte, error) {
	if e == nil || e.httpExec == nil {
		return nil, fmt.Errorf("codex auto executor: http executor is nil")
	}
	return e.httpExec.ReadQuotaUsage(ctx, auth)
}
