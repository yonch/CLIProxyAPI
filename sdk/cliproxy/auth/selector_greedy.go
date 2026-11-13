package auth

import (
	"context"
	"strings"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// GreedySelector uses observed reset schedules without changing quota state.
// Existing availability, priority and transport preferences remain authoritative.
type GreedySelector struct{}

func (s *GreedySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := time.Now()
	available, err := getSelectorAvailableAuths(ctx, auths, provider, model, now)
	if err != nil {
		return nil, err
	}
	available = preferCodexWebsocketAuths(ctx, provider, available)
	var best *Auth
	for _, a := range available {
		if best == nil || greedyAuthLess(a, best, now) {
			best = a
		}
	}
	return best, nil
}

func greedyAuthLess(a, b *Auth, now time.Time) bool {
	if au, bu := greedyUnobserved(a), greedyUnobserved(b); au != bu {
		return au
	}
	as, bs := EffectiveQuotaResetSchedule(a), EffectiveQuotaResetSchedule(b)
	for _, pair := range [][2]time.Time{{as.WeeklyResetAt, bs.WeeklyResetAt}, {as.FiveHourResetAt, bs.FiveHourResetAt}} {
		af, bf := pair[0].After(now), pair[1].After(now)
		if af != bf {
			return af
		}
		if af && !pair[0].Equal(pair[1]) {
			return pair[0].Before(pair[1])
		}
	}
	return a.ID < b.ID
}

// greedyUnobserved reports a credential whose reset schedule could be observed but
// has not been yet. It ranks first so one request returns its reset headers;
// otherwise an idle credential whose usage reads fail would never be ranked.
func greedyUnobserved(a *Auth) bool {
	switch strings.ToLower(strings.TrimSpace(a.Provider)) {
	case "claude", "codex":
		return a.QuotaResetSchedule.ObservedAt.IsZero() && a.Quota.ObservedAt.IsZero()
	}
	return false
}

func (v *readyView) pickGreedy(predicate func(*scheduledAuth) bool) *scheduledAuth {
	now := time.Now()
	var best *scheduledAuth
	for _, entry := range v.flat {
		if entry == nil || entry.auth == nil || (predicate != nil && !predicate(entry)) {
			continue
		}
		if best == nil || greedyAuthLess(entry.auth, best.auth, now) {
			best = entry
		}
	}
	return best
}
