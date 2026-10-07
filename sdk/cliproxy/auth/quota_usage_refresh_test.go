package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	internalconfig "github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type quotaUsageTestExecutor struct {
	schedulerTestExecutor
	read func(context.Context, *Auth) ([]byte, error)
}

func (e quotaUsageTestExecutor) ReadQuotaUsage(ctx context.Context, auth *Auth) ([]byte, error) {
	return e.read(ctx, auth)
}

type quotaUsageTestRTProvider struct{ rt http.RoundTripper }

func (p quotaUsageTestRTProvider) RoundTripperFor(*Auth) http.RoundTripper { return p.rt }

func quotaUsageTestAuth(id, provider string) *Auth {
	return &Auth{ID: id, Provider: provider, Status: StatusActive, Metadata: map[string]any{
		"type": provider, "access_token": "test-token-" + id, "account_id": "account-" + id,
		"expired": time.Now().Add(240 * time.Hour).Format(time.RFC3339),
	}}
}

func quotaUsageClaudeBody(weekly, five time.Time) []byte {
	return []byte(fmt.Sprintf(`{"seven_day":{"utilization":31,"resets_at":%q},"five_hour":{"utilization":14,"resets_at":%q}}`,
		weekly.UTC().Format(time.RFC3339), five.UTC().Format(time.RFC3339)))
}

func quotaUsageCodexBody(weekly time.Time) []byte {
	return []byte(fmt.Sprintf(`{"rate_limit":{"primary_window":{"used_percent":9,"limit_window_seconds":604800,"reset_at":%d},"secondary_window":null}}`, weekly.Unix()))
}

func newQuotaUsageTestManager(t *testing.T, read func(context.Context, *Auth) ([]byte, error), auths ...*Auth) *Manager {
	t.Helper()
	m := NewManager(nil, nil, nil)
	for _, provider := range []string{"claude", "codex", "kimi"} {
		m.RegisterExecutor(quotaUsageTestExecutor{schedulerTestExecutor{provider: provider}, read})
	}
	for _, auth := range auths {
		if _, err := m.Register(WithSkipPersist(context.Background()), auth); err != nil {
			t.Fatal(err)
		}
	}
	return m
}

func TestRefreshQuotaResetScheduleEligibility(t *testing.T) {
	weekly := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	five := time.Now().Add(2 * time.Hour).Truncate(time.Second)
	for _, tc := range []struct {
		name     string
		auth     func() *Auth
		id       string
		home     bool
		plainExe bool
		eligible bool
	}{
		{name: "claude oauth", auth: func() *Auth { return quotaUsageTestAuth("claude-a", "claude") }, eligible: true},
		{name: "codex oauth", auth: func() *Auth { return quotaUsageTestAuth("codex-a", "codex") }, eligible: true},
		{name: "disabled", auth: func() *Auth { a := quotaUsageTestAuth("claude-a", "claude"); a.Disabled = true; return a }},
		{name: "status disabled", auth: func() *Auth { a := quotaUsageTestAuth("claude-a", "claude"); a.Status = StatusDisabled; return a }},
		{name: "deleted", auth: func() *Auth { return quotaUsageTestAuth("claude-a", "claude") }, id: "claude-missing"},
		{name: "api key", auth: func() *Auth {
			return &Auth{ID: "claude-key", Provider: "claude", Attributes: map[string]string{"api_key": "test-api-key"}}
		}},
		{name: "oauth with api key attribute", auth: func() *Auth {
			a := quotaUsageTestAuth("claude-a", "claude")
			a.Attributes = map[string]string{"api_key": "test-api-key"}
			return a
		}},
		{name: "expired token", auth: func() *Auth {
			a := quotaUsageTestAuth("claude-a", "claude")
			a.Metadata["expired"] = time.Now().Add(-time.Minute).Format(time.RFC3339)
			return a
		}},
		{name: "no token", auth: func() *Auth {
			a := quotaUsageTestAuth("claude-a", "claude")
			delete(a.Metadata, "access_token")
			return a
		}},
		{name: "kimi executor embeds reader", auth: func() *Auth { return quotaUsageTestAuth("kimi-a", "kimi") }},
		{name: "home mode", auth: func() *Auth { return quotaUsageTestAuth("claude-a", "claude") }, home: true},
		{name: "executor without reader", auth: func() *Auth { return quotaUsageTestAuth("claude-a", "claude") }, plainExe: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reads atomic.Int32
			auth := tc.auth()
			m := newQuotaUsageTestManager(t, func(_ context.Context, a *Auth) ([]byte, error) {
				reads.Add(1)
				if a.Provider == "codex" {
					return quotaUsageCodexBody(weekly), nil
				}
				return quotaUsageClaudeBody(weekly, five), nil
			}, auth)
			if tc.plainExe {
				m.RegisterExecutor(schedulerTestExecutor{provider: "claude"})
			}
			if tc.home {
				cfg := &internalconfig.Config{}
				cfg.Home.Enabled = true
				m.SetConfig(cfg)
			}
			id := auth.ID
			if tc.id != "" {
				id = tc.id
			}
			err := m.RefreshQuotaResetSchedule(context.Background(), id, time.Second)
			if tc.eligible {
				if err != nil || reads.Load() != 1 {
					t.Fatalf("err=%v reads=%d, want one recorded read", err, reads.Load())
				}
				got, _ := m.GetByID(id)
				if !got.QuotaResetSchedule.WeeklyResetAt.Equal(weekly) {
					t.Fatalf("schedule = %+v, want weekly %v", got.QuotaResetSchedule, weekly)
				}
				return
			}
			if !errors.Is(err, ErrQuotaUsageNotEligible) || reads.Load() != 0 {
				t.Fatalf("err=%v reads=%d, want ineligible without a read", err, reads.Load())
			}
		})
	}
}

func TestRefreshQuotaResetScheduleFailureRetainsObservation(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	prior := QuotaResetSchedule{WeeklyResetAt: now.Add(72 * time.Hour), FiveHourResetAt: now.Add(3 * time.Hour), ObservedAt: now.Add(-time.Minute)}
	for _, tc := range []struct {
		name string
		body []byte
		err  error
	}{
		{name: "network error", err: errors.New("dial tcp: connection refused")},
		{name: "rejected status", err: errors.New("fetch Claude OAuth usage failed with status 401")},
		{name: "empty response", body: []byte(`{}`)},
		{name: "malformed response", body: []byte(`{"seven_day":`)},
		{name: "no reset window", body: []byte(`{"seven_day":{"utilization":30},"five_hour":{"utilization":0}}`)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newQuotaUsageTestManager(t, func(context.Context, *Auth) ([]byte, error) { return tc.body, tc.err }, quotaUsageTestAuth("claude-a", "claude"))
			before := m.RecordQuotaResetScheduleIfUnchanged(context.Background(), mustGetAuth(t, m, "claude-a"), prior)
			if before == nil {
				t.Fatal("prior schedule not recorded")
			}
			if err := m.RefreshQuotaResetSchedule(context.Background(), "claude-a", time.Second); err == nil || errors.Is(err, ErrQuotaUsageNotEligible) {
				t.Fatalf("err = %v, want read failure", err)
			}
			if after := mustGetAuth(t, m, "claude-a"); !reflect.DeepEqual(before, after) {
				t.Fatalf("failed read changed auth: schedule %+v -> %+v", before.QuotaResetSchedule, after.QuotaResetSchedule)
			}
		})
	}

	t.Run("partial window keeps unexpired prior window", func(t *testing.T) {
		weekly := now.Add(48 * time.Hour)
		body := []byte(fmt.Sprintf(`{"seven_day":{"utilization":31,"resets_at":%q},"five_hour":{"utilization":0,"resets_at":null}}`, weekly.UTC().Format(time.RFC3339)))
		m := newQuotaUsageTestManager(t, func(context.Context, *Auth) ([]byte, error) { return body, nil }, quotaUsageTestAuth("claude-a", "claude"))
		m.RecordQuotaResetScheduleIfUnchanged(context.Background(), mustGetAuth(t, m, "claude-a"), prior)
		if err := m.RefreshQuotaResetSchedule(context.Background(), "claude-a", time.Second); err != nil {
			t.Fatal(err)
		}
		got := mustGetAuth(t, m, "claude-a").QuotaResetSchedule
		if !got.WeeklyResetAt.Equal(weekly) || !got.FiveHourResetAt.Equal(prior.FiveHourResetAt) {
			t.Fatalf("schedule = %+v, want new weekly and prior five-hour", got)
		}
	})
}

func mustGetAuth(t *testing.T, m *Manager, id string) *Auth {
	t.Helper()
	auth, ok := m.GetByID(id)
	if !ok {
		t.Fatalf("auth %s missing", id)
	}
	return auth
}

func TestRefreshQuotaResetScheduleRejectsCredentialChangedDuringRead(t *testing.T) {
	weekly := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	for _, tc := range []struct {
		name   string
		change func(*testing.T, *Manager, *Auth)
		gone   bool
	}{
		{name: "token refreshed", change: func(t *testing.T, m *Manager, a *Auth) {
			updated := a.Clone()
			updated.Metadata["access_token"] = "test-token-refreshed"
			if _, err := m.UpdateRefreshedAuth(context.Background(), a, updated); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "disabled", change: func(t *testing.T, m *Manager, a *Auth) {
			updated := a.Clone()
			updated.Disabled = true
			updated.Status = StatusDisabled
			if _, err := m.Update(WithSkipPersist(context.Background()), updated); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "account replaced", change: func(t *testing.T, m *Manager, a *Auth) {
			updated := a.Clone()
			updated.Metadata["account_id"] = "account-other"
			if _, err := m.Update(WithSkipPersist(context.Background()), updated); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "deleted", gone: true, change: func(_ *testing.T, m *Manager, a *Auth) { m.Remove(context.Background(), a.ID) }},
		{name: "deleted and re-added", change: func(t *testing.T, m *Manager, a *Auth) {
			m.Remove(context.Background(), a.ID)
			if _, err := m.Register(WithSkipPersist(context.Background()), quotaUsageTestAuth(a.ID, a.Provider)); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m *Manager
			m = newQuotaUsageTestManager(t, func(_ context.Context, a *Auth) ([]byte, error) {
				tc.change(t, m, a)
				return quotaUsageCodexBody(weekly), nil
			}, quotaUsageTestAuth("codex-a", "codex"))
			if err := m.RefreshQuotaResetSchedule(context.Background(), "codex-a", time.Second); !errors.Is(err, ErrQuotaUsageObservationRejected) {
				t.Fatalf("err = %v, want rejected observation", err)
			}
			got, ok := m.GetByID("codex-a")
			if ok == tc.gone {
				t.Fatalf("auth present=%v, want %v", ok, !tc.gone)
			}
			if ok && !got.QuotaResetSchedule.ObservedAt.IsZero() {
				t.Fatalf("stale read recorded: %+v", got.QuotaResetSchedule)
			}
		})
	}
}

func TestRefreshQuotaResetScheduleTimeoutAndCancellation(t *testing.T) {
	blocking := func(started chan<- struct{}) func(context.Context, *Auth) ([]byte, error) {
		return func(ctx context.Context, _ *Auth) ([]byte, error) {
			if started != nil {
				close(started)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		}
	}

	t.Run("timeout", func(t *testing.T) {
		var deadline time.Time
		m := newQuotaUsageTestManager(t, func(ctx context.Context, a *Auth) ([]byte, error) {
			deadline, _ = ctx.Deadline()
			return blocking(nil)(ctx, a)
		}, quotaUsageTestAuth("claude-a", "claude"))
		start := time.Now()
		err := m.RefreshQuotaResetSchedule(context.Background(), "claude-a", 20*time.Millisecond)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want deadline exceeded", err)
		}
		if deadline.IsZero() || deadline.After(start.Add(time.Second)) {
			t.Fatalf("read deadline = %v, want bounded by the read timeout", deadline)
		}
		if got := mustGetAuth(t, m, "claude-a"); !got.QuotaResetSchedule.ObservedAt.IsZero() {
			t.Fatalf("timed out read recorded: %+v", got.QuotaResetSchedule)
		}
	})

	t.Run("parent canceled", func(t *testing.T) {
		started := make(chan struct{})
		m := newQuotaUsageTestManager(t, blocking(started), quotaUsageTestAuth("claude-a", "claude"))
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- m.RefreshQuotaResetSchedule(ctx, "claude-a", time.Hour) }()
		<-started
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want canceled", err)
		}
	})
}

func TestRefreshQuotaResetScheduleUsesRegisteredTransport(t *testing.T) {
	rt := quotaUsageTestRTProvider{rt: http.DefaultTransport}
	var got http.RoundTripper
	m := newQuotaUsageTestManager(t, func(ctx context.Context, _ *Auth) ([]byte, error) {
		got, _ = ctx.Value("cliproxy.roundtripper").(http.RoundTripper)
		return quotaUsageCodexBody(time.Now().Add(time.Hour)), nil
	}, quotaUsageTestAuth("codex-a", "codex"))
	m.SetRoundTripperProvider(rt)
	if err := m.RefreshQuotaResetSchedule(context.Background(), "codex-a", time.Second); err != nil {
		t.Fatal(err)
	}
	if got != rt.rt {
		t.Fatal("usage read did not receive the credential's registered transport")
	}
}

// TestRefreshQuotaResetScheduleFeedsGreedyRanking restores the restart case: a credential
// with no in-memory observation ranks behind one with a known reset until its usage is read.
func TestRefreshQuotaResetScheduleFeedsGreedyRanking(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	soon, later := now.Add(24*time.Hour), now.Add(72*time.Hour)
	a := quotaUsageTestAuth("greedy-refresh-a", "claude")
	b := quotaUsageTestAuth("greedy-refresh-b", "claude")
	b.QuotaResetSchedule = QuotaResetSchedule{WeeklyResetAt: later, ObservedAt: now.Add(-time.Minute)}
	reg := registry.GetGlobalRegistry()
	for _, auth := range []*Auth{a, b} {
		id := auth.ID
		reg.RegisterClient(id, "claude", []*registry.ModelInfo{{ID: "greedy-refresh-model"}})
		t.Cleanup(func() { reg.UnregisterClient(id) })
	}
	m := NewManager(nil, &GreedySelector{}, nil)
	m.RegisterExecutor(quotaUsageTestExecutor{schedulerTestExecutor{provider: "claude"}, func(_ context.Context, auth *Auth) ([]byte, error) {
		if auth.ID != a.ID {
			return nil, errors.New("unexpected read")
		}
		return quotaUsageClaudeBody(soon, now.Add(time.Hour)), nil
	}})
	for _, auth := range []*Auth{a, b} {
		if _, err := m.Register(WithSkipPersist(context.Background()), auth); err != nil {
			t.Fatal(err)
		}
	}
	pick := func() string {
		t.Helper()
		got, _, err := m.pickNext(context.Background(), "claude", "greedy-refresh-model", cliproxyexecutor.Options{}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return got.ID
	}
	if got := pick(); got != b.ID {
		t.Fatalf("before refresh picked %s, want the only known reset %s", got, b.ID)
	}
	before := mustGetAuth(t, m, a.ID)
	if err := m.RefreshQuotaResetSchedule(context.Background(), a.ID, time.Second); err != nil {
		t.Fatal(err)
	}
	if got := pick(); got != a.ID {
		t.Fatalf("after refresh picked %s, want soonest reset %s", got, a.ID)
	}
	after := mustGetAuth(t, m, a.ID)
	if !reflect.DeepEqual(before.Quota, after.Quota) || before.Unavailable != after.Unavailable || before.Status != after.Status ||
		!reflect.DeepEqual(before.Metadata, after.Metadata) {
		t.Fatal("usage refresh changed availability, quota state or credential metadata")
	}
}
