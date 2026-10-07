package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// QuotaUsageReader is an optional ProviderExecutor capability. ReadQuotaUsage reads the
// credential's subscription usage endpoint and returns the raw response body. A non-2xx
// response is an error. Implementations must send the credential only to the provider's
// own usage endpoint and must refuse credentials the endpoint cannot serve with an error
// wrapping ErrQuotaUsageNotEligible, before any network access.
// Eligibility is also checked by provider because Go embedding passes the capability on:
// KimiExecutor embeds ClaudeExecutor, and a Kimi token must never reach Anthropic.
type QuotaUsageReader interface {
	ReadQuotaUsage(ctx context.Context, auth *Auth) ([]byte, error)
}

var (
	// ErrQuotaUsageNotEligible reports a credential the usage refresh skips without network access.
	ErrQuotaUsageNotEligible = errors.New("credential is not eligible for quota usage refresh")
	// ErrQuotaUsageObservationRejected reports a read whose credential changed before it was recorded.
	ErrQuotaUsageObservationRejected = errors.New("quota usage observation rejected because the credential changed")
)

func quotaUsageRefreshEligible(auth *Auth, now time.Time) bool {
	if auth == nil || auth.Disabled || auth.Status == StatusDisabled || auth.AuthKind() != AuthKindOAuth ||
		authAttribute(auth, AttributeAPIKey) != "" || !auth.HasValidAccessToken(now) {
		return false
	}
	return auth.Provider == "claude" || auth.Provider == "codex"
}

// RefreshQuotaResetSchedule reads one enabled Claude or Codex OAuth credential's usage
// endpoint and publishes its reset times through RecordQuotaResetScheduleIfUnchanged.
// The read uses the credential's registered transport and is bounded by timeout. Any
// failure, unusable response or credential change during the read leaves the previous
// observation untouched. Tokens, availability, cooldowns and persistence are not changed.
func (m *Manager) RefreshQuotaResetSchedule(ctx context.Context, authID string, timeout time.Duration) error {
	if m == nil {
		return ErrQuotaUsageNotEligible
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config); cfg != nil && cfg.Home.Enabled {
		return ErrQuotaUsageNotEligible
	}
	snapshot, ok := m.GetByID(authID)
	if !ok || !quotaUsageRefreshEligible(snapshot, time.Now()) {
		return ErrQuotaUsageNotEligible
	}
	exec, ok := m.Executor(snapshot.Provider)
	if !ok {
		return ErrQuotaUsageNotEligible
	}
	reader, ok := exec.(QuotaUsageReader)
	if !ok {
		return ErrQuotaUsageNotEligible
	}

	readCtx := ctx
	if rt := m.roundTripperFor(snapshot); rt != nil {
		readCtx = context.WithValue(readCtx, roundTripperContextKey{}, rt)
		readCtx = context.WithValue(readCtx, "cliproxy.roundtripper", rt)
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		readCtx, cancel = context.WithTimeout(readCtx, timeout)
		defer cancel()
	}
	body, errRead := reader.ReadQuotaUsage(readCtx, snapshot.Clone())
	if errRead != nil {
		return fmt.Errorf("read %s quota usage: %w", snapshot.Provider, errRead)
	}
	schedule, ok := QuotaResetScheduleFromUsage(snapshot.Provider, body, time.Now())
	if !ok {
		return fmt.Errorf("read %s quota usage: response has no usable reset window", snapshot.Provider)
	}
	if m.RecordQuotaResetScheduleIfUnchanged(ctx, snapshot, schedule) == nil {
		return ErrQuotaUsageObservationRejected
	}
	return nil
}
