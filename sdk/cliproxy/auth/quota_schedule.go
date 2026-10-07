package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
)

// QuotaResetSchedule is an in-memory observation from a provider usage endpoint.
// It does not determine credential availability or release quota cooldowns.
type QuotaResetSchedule struct {
	WeeklyResetAt   time.Time `json:"weekly_reset_at"`
	FiveHourResetAt time.Time `json:"five_hour_reset_at"`
	ObservedAt      time.Time `json:"observed_at"`
}

func quotaScheduleIdentityMatches(a, b *Auth) bool {
	for _, key := range []string{"account_id", "email", "sub"} {
		left, _ := a.Metadata[key].(string)
		right, _ := b.Metadata[key].(string)
		if left != right {
			return false
		}
	}
	return true
}

// EffectiveQuotaResetSchedule merges the newest available provider observation.
// Header observations arrive on ordinary requests and require no usage probe.
func EffectiveQuotaResetSchedule(auth *Auth) QuotaResetSchedule {
	if auth == nil {
		return QuotaResetSchedule{}
	}
	schedule := auth.QuotaResetSchedule
	if !auth.Quota.ObservedAt.After(schedule.ObservedAt) {
		return schedule
	}
	headers := make(http.Header, len(auth.Quota.Signals))
	for name, value := range auth.Quota.Signals {
		headers.Set(name, value)
	}
	observed := quotaScheduleFromHeaders(auth.Provider, headers, auth.Quota.ObservedAt)
	if observed.WeeklyResetAt.IsZero() && observed.FiveHourResetAt.IsZero() {
		return schedule
	}
	return mergeQuotaResetSchedule(schedule, observed)
}

// ObservedAt identifies the latest merged observation, not the age of every
// reset field. A missing window retains its prior reset only until that reset.
func mergeQuotaResetSchedule(previous, observed QuotaResetSchedule) QuotaResetSchedule {
	if observed.WeeklyResetAt.IsZero() && previous.WeeklyResetAt.After(observed.ObservedAt) {
		observed.WeeklyResetAt = previous.WeeklyResetAt
	}
	if observed.FiveHourResetAt.IsZero() && previous.FiveHourResetAt.After(observed.ObservedAt) {
		observed.FiveHourResetAt = previous.FiveHourResetAt
	}
	return observed
}

func quotaScheduleFromHeaders(provider string, headers http.Header, observedAt time.Time) QuotaResetSchedule {
	schedule := QuotaResetSchedule{ObservedAt: observedAt}
	reset := func(name string) time.Time {
		seconds, err := strconv.ParseInt(strings.TrimSpace(headers.Get(name)), 10, 64)
		if err != nil || seconds <= 0 || seconds > 253402300799 {
			return time.Time{}
		}
		return time.Unix(seconds, 0).UTC()
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		schedule.WeeklyResetAt = reset("Anthropic-Ratelimit-Unified-7d-Reset")
		schedule.FiveHourResetAt = reset("Anthropic-Ratelimit-Unified-5h-Reset")
	case "codex":
		seenWindows := make(map[int64]bool, 2)
		for _, window := range []string{"primary", "secondary"} {
			prefix := "X-Codex-" + window
			minutes, err := strconv.ParseInt(strings.TrimSpace(headers.Get(prefix+"-Window-Minutes")), 10, 64)
			if err != nil || (minutes != 10080 && minutes != 300) {
				continue
			}
			if seenWindows[minutes] {
				return QuotaResetSchedule{}
			}
			seenWindows[minutes] = true
			at := reset(prefix + "-Reset-At")
			if at.IsZero() {
				seconds, errSeconds := strconv.ParseInt(strings.TrimSpace(headers.Get(prefix+"-Reset-After-Seconds")), 10, 64)
				if errSeconds == nil && seconds >= 0 && seconds <= 604800 && !observedAt.IsZero() {
					at = observedAt.Add(time.Duration(seconds) * time.Second)
				}
			}
			if minutes == 10080 {
				schedule.WeeklyResetAt = at
			} else {
				schedule.FiveHourResetAt = at
			}
		}
	}
	return schedule
}

func quotaUsageAlias(record map[string]json.RawMessage, names ...string) json.RawMessage {
	var selected json.RawMessage
	for _, name := range names {
		if value, ok := record[name]; ok {
			if selected != nil && !bytes.Equal(bytes.TrimSpace(selected), bytes.TrimSpace(value)) {
				return json.RawMessage(`!`)
			}
			selected = value
		}
	}
	return selected
}

// QuotaResetScheduleFromUsage normalizes a Claude /api/oauth/usage or Codex
// /backend-api/wham/usage response body. It reports false when the body is
// malformed, ambiguous or carries no reset window, so callers keep the prior observation.
func QuotaResetScheduleFromUsage(provider string, body []byte, observedAt time.Time) (QuotaResetSchedule, bool) {
	schedule := QuotaResetSchedule{ObservedAt: observedAt}
	var payload map[string]json.RawMessage
	if json.Unmarshal(body, &payload) != nil || payload == nil {
		return schedule, false
	}
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "claude":
		for _, key := range []string{"seven_day", "five_hour"} {
			var window struct {
				ResetAt     string   `json:"resets_at"`
				Utilization *float64 `json:"utilization"`
			}
			if json.Unmarshal(payload[key], &window) != nil || window.Utilization == nil || *window.Utilization < 0 {
				return schedule, false
			}
			if window.ResetAt == "" {
				continue
			}
			at, err := time.Parse(time.RFC3339Nano, window.ResetAt)
			if err != nil {
				return schedule, false
			}
			if key == "seven_day" {
				schedule.WeeklyResetAt = at
			} else {
				schedule.FiveHourResetAt = at
			}
		}
	case "codex":
		var limit map[string]json.RawMessage
		if json.Unmarshal(quotaUsageAlias(payload, "rate_limit", "rateLimit"), &limit) != nil || limit == nil {
			return schedule, false
		}
		for _, names := range [][]string{{"primary_window", "primaryWindow"}, {"secondary_window", "secondaryWindow"}} {
			raw := quotaUsageAlias(limit, names...)
			if string(bytes.TrimSpace(raw)) == "null" {
				continue
			}
			var window map[string]json.RawMessage
			if json.Unmarshal(raw, &window) != nil || window == nil {
				return schedule, false
			}
			var seconds, resetAt int64
			if json.Unmarshal(quotaUsageAlias(window, "limit_window_seconds", "limitWindowSeconds"), &seconds) != nil ||
				json.Unmarshal(quotaUsageAlias(window, "reset_at", "resetAt"), &resetAt) != nil || resetAt <= 0 || resetAt > 253402300799 {
				return schedule, false
			}
			at := time.Unix(resetAt, 0).UTC()
			if seconds == 604800 {
				if !schedule.WeeklyResetAt.IsZero() {
					return schedule, false
				}
				schedule.WeeklyResetAt = at
			} else if seconds == 18000 {
				if !schedule.FiveHourResetAt.IsZero() {
					return schedule, false
				}
				schedule.FiveHourResetAt = at
			}
		}
	default:
		return schedule, false
	}
	return schedule, !schedule.WeeklyResetAt.IsZero() || !schedule.FiveHourResetAt.IsZero()
}

// RecordQuotaResetScheduleIfUnchanged publishes usage reset times only while
// the credential inspected before the request remains current. Availability,
// cooldowns, tokens and persisted credential files are left untouched.
func (m *Manager) RecordQuotaResetScheduleIfUnchanged(ctx context.Context, expected *Auth, schedule QuotaResetSchedule) *Auth {
	if m == nil || expected == nil || expected.ID == "" || schedule.ObservedAt.IsZero() {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	release, err := m.lockAuthMutationContext(ctx, expected.ID)
	if err != nil {
		return nil
	}
	defer release()
	m.mu.Lock()
	current := m.auths[expected.ID]
	cfg, _ := m.runtimeConfig.Load().(*internalconfig.Config)
	if ctx.Err() != nil || (cfg != nil && cfg.Home.Enabled) || current == nil || current.Disabled || current.Status == StatusDisabled ||
		current.Provider != expected.Provider || current.RegistrationEpoch != expected.RegistrationEpoch || current.Generation != expected.Generation ||
		current.QuotaResetSchedule.ObservedAt.After(schedule.ObservedAt) {
		m.mu.Unlock()
		return nil
	}
	updated := current.Clone()
	updated.QuotaResetSchedule = mergeQuotaResetSchedule(current.QuotaResetSchedule, schedule)
	updated.Generation++
	updated.UpdatedAt = schedule.ObservedAt
	m.auths[updated.ID] = updated
	m.notifyAuthChangeLocked(updated.ID)
	snapshot := updated.Clone()
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(snapshot)
	}
	return snapshot
}
