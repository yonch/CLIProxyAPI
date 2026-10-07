package management

import (
	"net/http"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func routingUsageRequestMatches(req *http.Request, auth *coreauth.Auth) bool {
	if req == nil || auth == nil || req.URL == nil || req.Method != http.MethodGet || req.Body != nil ||
		req.URL.Scheme != "https" || req.URL.User != nil || req.URL.RawQuery != "" || req.URL.ForceQuery || req.URL.Fragment != "" || req.URL.RawPath != "" {
		return false
	}
	token, _ := auth.Metadata["access_token"].(string)
	token = strings.TrimSpace(token)
	if token == "" || len(req.Header.Values("Authorization")) != 1 || req.Header.Get("Authorization") != "Bearer "+token || req.Header.Get("Cookie") != "" || req.Header.Get("X-Api-Key") != "" ||
		(req.Host != "" && req.Host != req.URL.Host) {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(auth.Provider)) {
	case "claude":
		return req.URL.Host == "api.anthropic.com" && req.URL.Path == "/api/oauth/usage"
	case "codex":
		if req.URL.Host != "chatgpt.com" || req.URL.Path != "/backend-api/wham/usage" {
			return false
		}
		account, _ := auth.Metadata["account_id"].(string)
		values := req.Header.Values("Chatgpt-Account-Id")
		return (strings.TrimSpace(account) == "" && len(values) == 0) || (account != "" && len(values) == 1 && values[0] == account)
	}
	return false
}
