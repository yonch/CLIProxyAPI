package cliproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

type quotaTestStore struct {
	auths []*coreauth.Auth
	saves atomic.Int32
}

func (s *quotaTestStore) List(context.Context) ([]*coreauth.Auth, error) {
	out := make([]*coreauth.Auth, 0, len(s.auths))
	for _, auth := range s.auths {
		out = append(out, auth.Clone())
	}
	return out, nil
}

func (s *quotaTestStore) Save(_ context.Context, auth *coreauth.Auth) (string, error) {
	s.saves.Add(1)
	return auth.ID, nil
}

func (s *quotaTestStore) Delete(context.Context, string) error { return nil }

type quotaTestRoundTripper func(*http.Request) (*http.Response, error)

func (f quotaTestRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type quotaTestRTProvider struct{ rt http.RoundTripper }

func (p quotaTestRTProvider) RoundTripperFor(*coreauth.Auth) http.RoundTripper { return p.rt }

func quotaTestResponse(req *http.Request, status int, contentType, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}

func codexWeeklyUsage(resetAt time.Time) string {
	return fmt.Sprintf(`{"plan_type":"pro","rate_limit":{"allowed":true,"limit_reached":false,"primary_window":{"used_percent":9,"limit_window_seconds":604800,"reset_after_seconds":%d,"reset_at":%d},"secondary_window":null},"additional_rate_limits":[]}`,
		int64(time.Until(resetAt).Seconds()), resetAt.Unix())
}

func quotaTestWaitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(5 * time.Second)
	defer timeout.Stop()
	for !cond() {
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

// TestQuotaUsageStartupSweepFeedsGreedyRouting runs the service with greedy routing, three
// Codex OAuth credentials, a full Claude OAuth credential, a Claude setup token and a
// disabled Codex credential. codex-a has the soonest known weekly reset but its usage read
// is rejected; codex-c has no in-memory observation, as after a restart, so it ranks last
// until the startup sweep shows it resets soonest. A new session must then go to codex-c.
func TestQuotaUsageStartupSweepFeedsGreedyRouting(t *testing.T) {
	const model = "gpt-5.5"
	now := time.Now().Truncate(time.Second)
	resetA, resetB, resetBRead, resetC := now.Add(48*time.Hour), now.Add(72*time.Hour), now.Add(60*time.Hour), now.Add(24*time.Hour)
	// Tokens expire well past every refresh lead and carry no refresh token, so the
	// auto-refresh loop has nothing due and no test path can reach a real token endpoint.
	expiry := now.Add(10 * 24 * time.Hour).Format(time.RFC3339)
	codexAuth := func(id, token string) *coreauth.Auth {
		return &coreauth.Auth{ID: id, Provider: "codex", Status: coreauth.StatusActive,
			Metadata: map[string]any{"type": "codex", "access_token": token, "account_id": "account-" + token, "expired": expiry}}
	}
	codexA, codexOff := codexAuth("codex-a", "tok-a"), codexAuth("codex-off", "tok-off")
	codexA.QuotaResetSchedule = coreauth.QuotaResetSchedule{WeeklyResetAt: resetA, ObservedAt: now.Add(-time.Minute)}
	codexB := codexAuth("codex-b", "tok-b")
	codexB.QuotaResetSchedule = coreauth.QuotaResetSchedule{WeeklyResetAt: resetB, ObservedAt: now.Add(-time.Minute)}
	codexOff.Disabled = true
	store := &quotaTestStore{auths: []*coreauth.Auth{
		codexA, codexB, codexAuth("codex-c", "tok-c"), codexOff,
		{ID: "claude-d", Provider: "claude", Status: coreauth.StatusActive,
			Metadata: map[string]any{"type": "claude", "access_token": "sk-ant-oat01-test-d", "expired": expiry}},
		{ID: "claude-setup", Provider: "claude", Status: coreauth.StatusActive,
			Metadata: map[string]any{"type": "claude", "access_token": "sk-ant-oat01-test-setup", "expired": expiry, "scope": "user:inference"}},
	}}
	for _, auth := range store.auths {
		id, provider := auth.ID, auth.Provider
		registry.GetGlobalRegistry().RegisterClient(id, provider, []*registry.ModelInfo{{ID: model}})
		t.Cleanup(func() { registry.GetGlobalRegistry().UnregisterClient(id) })
	}

	var mu sync.Mutex
	var usageReads, responses, unexpected []string
	rt := quotaTestRoundTripper(func(req *http.Request) (*http.Response, error) {
		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		route := req.Method + " " + req.URL.Host + req.URL.Path
		mu.Lock()
		defer mu.Unlock()
		switch route {
		case "GET chatgpt.com/backend-api/wham/usage":
			usageReads = append(usageReads, token)
			if req.Header.Get("Chatgpt-Account-Id") != "account-"+token {
				unexpected = append(unexpected, "missing account header for "+token)
			}
			switch token {
			case "tok-a":
				return quotaTestResponse(req, http.StatusTooManyRequests, "application/json", `{"error":"rate limited"}`), nil
			case "tok-b":
				return quotaTestResponse(req, http.StatusOK, "application/json", codexWeeklyUsage(resetBRead)), nil
			case "tok-c":
				return quotaTestResponse(req, http.StatusOK, "application/json", codexWeeklyUsage(resetC)), nil
			}
		case "GET api.anthropic.com/api/oauth/usage":
			usageReads = append(usageReads, token)
			if req.Header.Get("Anthropic-Beta") != "oauth-2025-04-20" {
				unexpected = append(unexpected, "missing anthropic-beta header")
			}
			return quotaTestResponse(req, http.StatusOK, "application/json",
				`{"five_hour":{"utilization":14.0,"resets_at":"2030-10-04T02:40:00.347417+00:00"},"seven_day":{"utilization":31.0,"resets_at":"2030-10-08T23:00:00.347435+00:00"}}`), nil
		case "POST chatgpt.com/backend-api/codex/responses":
			responses = append(responses, token)
			completed := fmt.Sprintf(`{"type":"response.completed","response":{"id":"resp-1","object":"response","status":"completed","model":%q,"output":[{"type":"message","id":"msg-1","role":"assistant","status":"completed","content":[{"type":"output_text","text":"ok","annotations":[]}]}],"usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2}}}`, model)
			return quotaTestResponse(req, http.StatusOK, "text/event-stream", "data: "+completed+"\n\n"), nil
		}
		unexpected = append(unexpected, route)
		return nil, errors.New("unexpected upstream request: " + route)
	})

	ln, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("listen: %v", errListen)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if errClose := ln.Close(); errClose != nil {
		t.Fatalf("close listener: %v", errClose)
	}
	authDir := t.TempDir()
	cfgPath := filepath.Join(authDir, "config.yaml")
	if errWrite := os.WriteFile(cfgPath, []byte("{}"), 0o644); errWrite != nil {
		t.Fatalf("write config: %v", errWrite)
	}
	cfg := &config.Config{Host: "127.0.0.1", Port: port, AuthDir: authDir}
	cfg.APIKeys = []string{"proxy-key"}
	cfg.Routing.Strategy = "greedy"
	manager := coreauth.NewManager(store, newRoutingSelector(normalizedRoutingRuntimeState(cfg)), nil)
	service, errBuild := NewBuilder().
		WithConfig(cfg).
		WithConfigPath(cfgPath).
		WithCoreAuthManager(manager).
		WithWatcherFactory(func(string, string, func(*config.Config)) (*WatcherWrapper, error) {
			return &WatcherWrapper{}, nil
		}).
		Build()
	if errBuild != nil {
		t.Fatalf("build service: %v", errBuild)
	}
	// Both execution and the background sweep read the transport from the provider.
	manager.SetRoundTripperProvider(quotaTestRTProvider{rt: rt})
	runCtx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- service.Run(runCtx) }()
	defer func() {
		cancel()
		select {
		case <-runDone:
		case <-time.After(10 * time.Second):
			t.Error("timed out waiting for service.Run to exit")
		}
	}()

	weeklyOf := func(id string) time.Time {
		auth, _ := manager.GetByID(id)
		return coreauth.EffectiveQuotaResetSchedule(auth).WeeklyResetAt
	}
	quotaTestWaitFor(t, "the startup sweep to record every readable credential", func() bool {
		mu.Lock()
		reads := len(usageReads)
		mu.Unlock()
		return reads == 4 && !weeklyOf("claude-d").IsZero() && weeklyOf("codex-b").Equal(resetBRead) && weeklyOf("codex-c").Equal(resetC)
	})

	mu.Lock()
	reads := append([]string(nil), usageReads...)
	sort.Strings(reads)
	if want := []string{"sk-ant-oat01-test-d", "tok-a", "tok-b", "tok-c"}; !reflect.DeepEqual(reads, want) {
		t.Errorf("usage reads = %v, want one per eligible credential %v", usageReads, want)
	}
	if len(unexpected) != 0 {
		t.Errorf("unexpected upstream traffic during the sweep (refreshes included): %v", unexpected)
	}
	mu.Unlock()
	if got := weeklyOf("codex-a"); !got.Equal(resetA) {
		t.Errorf("codex-a reset after a rejected read = %v, want previous %v", got, resetA)
	}
	if got := weeklyOf("claude-setup"); !got.IsZero() {
		t.Errorf("setup token received a schedule: %v", got)
	}
	if saves := store.saves.Load(); saves != 0 {
		t.Errorf("token store saves during the sweep = %d, want 0", saves)
	}
	for _, id := range []string{"codex-a", "codex-b", "codex-c", "claude-d"} {
		auth, _ := manager.GetByID(id)
		// A refresh attempt sets NextRefreshAfter when it starts and LastRefreshedAt on success.
		if !auth.NextRefreshAfter.IsZero() || !auth.LastRefreshedAt.IsZero() {
			t.Errorf("%s was refreshed during the sweep", id)
		}
	}

	var resp *http.Response
	var errDo error
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		req, errRequest := http.NewRequest(http.MethodPost, fmt.Sprintf("http://127.0.0.1:%d/v1/responses", port),
			strings.NewReader(fmt.Sprintf(`{"model":%q,"input":"hello"}`, model)))
		if errRequest != nil {
			t.Fatalf("new request: %v", errRequest)
		}
		req.Header.Set("Authorization", "Bearer proxy-key")
		req.Header.Set("Content-Type", "application/json")
		if resp, errDo = http.DefaultClient.Do(req); errDo == nil {
			break
		}
	}
	if errDo != nil {
		t.Fatalf("proxy request: %v", errDo)
	}
	body, _ := io.ReadAll(resp.Body)
	if errClose := resp.Body.Close(); errClose != nil {
		t.Errorf("close response body: %v", errClose)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status = %d, body = %s", resp.StatusCode, body)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(responses) != 1 || responses[0] != "tok-c" {
		t.Fatalf("new session went to %v, want [tok-c]: the swept credential resets soonest", responses)
	}
}

type quotaRefreshTestExecutor struct {
	*syncTestExecutor
	provider string
	read     func(context.Context, *coreauth.Auth) ([]byte, error)
}

func (e quotaRefreshTestExecutor) Identifier() string { return e.provider }

func (e quotaRefreshTestExecutor) ReadQuotaUsage(ctx context.Context, auth *coreauth.Auth) ([]byte, error) {
	return e.read(ctx, auth)
}

func newQuotaRefreshTestService(t *testing.T, read func(context.Context, *coreauth.Auth) ([]byte, error), ids ...string) *Service {
	t.Helper()
	manager := coreauth.NewManager(nil, nil, nil)
	manager.RegisterExecutor(quotaRefreshTestExecutor{provider: "claude", read: read})
	for _, id := range ids {
		auth := &coreauth.Auth{ID: id, Provider: "claude", Status: coreauth.StatusActive,
			Metadata: map[string]any{"type": "claude", "access_token": "sk-ant-oat01-test-" + id}}
		if _, err := manager.Register(coreauth.WithSkipPersist(context.Background()), auth); err != nil {
			t.Fatal(err)
		}
	}
	return &Service{cfg: &config.Config{}, coreManager: manager}
}

func quotaRefreshClaudeUsage(weekly time.Time) []byte {
	return []byte(fmt.Sprintf(`{"seven_day":{"utilization":10,"resets_at":%q},"five_hour":{"utilization":0,"resets_at":null}}`, weekly.UTC().Format(time.RFC3339)))
}

// TestQuotaUsageRefreshLoopSweepsAtStartupAndPeriodically checks that the loop reads before
// its first tick, reads again on every tick, and exits when its context ends.
func TestQuotaUsageRefreshLoopSweepsAtStartupAndPeriodically(t *testing.T) {
	weekly := time.Now().Add(24 * time.Hour).Truncate(time.Second)
	reads := make(chan string, 64)
	service := newQuotaRefreshTestService(t, func(_ context.Context, auth *coreauth.Auth) ([]byte, error) {
		reads <- auth.ID
		return quotaRefreshClaudeUsage(weekly), nil
	}, "claude-a")

	t.Run("startup", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			service.runQuotaUsageRefresh(ctx, time.Hour, time.Second)
			close(done)
		}()
		select {
		case <-reads:
		case <-time.After(5 * time.Second):
			t.Fatal("no read before the first tick")
		}
		// The read signals before it is recorded, and a canceled sweep discards its result.
		quotaTestWaitFor(t, "the startup read to be recorded", func() bool {
			auth, _ := service.coreManager.GetByID("claude-a")
			return auth.QuotaResetSchedule.WeeklyResetAt.Equal(weekly)
		})
		cancel()
		<-done
	})

	t.Run("periodic", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() {
			service.runQuotaUsageRefresh(ctx, 5*time.Millisecond, time.Second)
			close(done)
		}()
		for i := 0; i < 3; i++ {
			select {
			case <-reads:
			case <-time.After(5 * time.Second):
				t.Fatalf("read %d did not happen", i+1)
			}
		}
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("refresh loop did not exit after cancellation")
		}
	})
}

// TestQuotaUsageRefreshSweepIsolatesFailures checks that one failing or hung read keeps its
// prior schedule and neither stalls nor aborts the reads after it, and that cancellation
// stops the sweep before the next credential is read.
func TestQuotaUsageRefreshSweepIsolatesFailures(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	prior := coreauth.QuotaResetSchedule{WeeklyResetAt: now.Add(72 * time.Hour), ObservedAt: now.Add(-time.Minute)}
	weekly := now.Add(24 * time.Hour)
	var mu sync.Mutex
	var order []string
	service := newQuotaRefreshTestService(t, func(ctx context.Context, auth *coreauth.Auth) ([]byte, error) {
		mu.Lock()
		order = append(order, auth.ID)
		mu.Unlock()
		switch auth.ID {
		case "claude-a":
			return nil, errors.New("fetch Claude OAuth usage failed with status 500")
		case "claude-b":
			<-ctx.Done()
			return nil, ctx.Err()
		}
		return quotaRefreshClaudeUsage(weekly), nil
	}, "claude-a", "claude-b", "claude-c")
	for _, id := range []string{"claude-a", "claude-b"} {
		auth, _ := service.coreManager.GetByID(id)
		if service.coreManager.RecordQuotaResetScheduleIfUnchanged(context.Background(), auth, prior) == nil {
			t.Fatalf("prior schedule for %s not recorded", id)
		}
	}

	service.refreshQuotaUsage(context.Background(), 20*time.Millisecond)
	for id, want := range map[string]time.Time{"claude-a": prior.WeeklyResetAt, "claude-b": prior.WeeklyResetAt, "claude-c": weekly} {
		auth, _ := service.coreManager.GetByID(id)
		if !auth.QuotaResetSchedule.WeeklyResetAt.Equal(want) {
			t.Errorf("%s weekly reset = %v, want %v", id, auth.QuotaResetSchedule.WeeklyResetAt, want)
		}
	}
	mu.Lock()
	if len(order) != 3 {
		t.Errorf("reads = %v, want all three credentials", order)
	}
	order = nil
	mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service.refreshQuotaUsage(ctx, time.Second)
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 0 {
		t.Errorf("canceled sweep read %v", order)
	}
}
